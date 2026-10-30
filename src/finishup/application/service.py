"""Frozen contracts shared by the ready application facade and service daemon."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Literal, Protocol, cast

from pydantic import BaseModel

from finishup.application.check_change import record_task_change_base, statement_input_paths
from finishup.application.coordination import (
    CoordinationParticipant,
    coordination_generation_superseded,
)
from finishup.application.egress import PrivacyCoordinator
from finishup.application.input_snapshot import InputSnapshotScope, record_input_snapshot
from finishup.application.lineage import LineageCoordinator, LineageSnapshot, LineageStatus
from finishup.application.lineage_recovery import (
    append_abandonment,
    extend_session_lease,
    lineage_recovery_runtime,
)
from finishup.application.observation_advice_semantic import ObservationAdviceSemanticSupervisor
from finishup.application.observation_verification import ObservationVerificationSupervisor
from finishup.application.projects import ProjectApplication
from finishup.application.result_delivery import (
    HOST_RESULT_BUDGET_BYTES,
    DeliveryPageSet,
    DeliveryPageStore,
    DeliverySource,
    brief_check_body,
    check_selector_code,
    content_digest,
    decode_handle,
    disclosure_identity,
    invalid_cursor,
    mcp_delivery_bytes,
    page_result,
    receipt_selector_code,
    receipt_selector_from_code,
    status_selector_code,
    status_selector_from_code,
)
from finishup.application.start import recover_delegation
from finishup.application.unit_of_work import run_publish_response_commit
from finishup.domain.coordination import (
    CoordinationError,
    CoordinationErrorCode,
    LineageAcceptance,
    SessionHealth,
    WorkState,
)
from finishup.domain.events import (
    LINEAGE_SERVICE_STAMPED_FAMILIES,
    AcceptedEvent,
    ChildAcceptedPayload,
    ChildDependenciesRecordedPayload,
    ChildRejectedPayload,
    ChildWrittenOffPayload,
    CoordinationContextRecordedPayload,
    CoordinationDispositionRecordedPayload,
    CoordinationObligationDeclaredPayload,
    DelegationCancelledPayload,
    DelegationDeclaredPayload,
    EventSchema,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    RequestedItemKind,
    RequestedItemRole,
    ResultRecordedPayload,
    RuntimeProfile,
    WorkAbandonedPayload,
    WorkCancelledPayload,
    WorkClosedPayload,
    WorkWrittenOffPayload,
    decode_payload,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    LocalDisclosureApproved,
    LocalDisclosureBlocked,
    LocalDisclosureSink,
    LocalDisclosureUnavailable,
    ProjectionAuditContext,
    ProjectionProvenanceContext,
)
from finishup.domain.receipts import ReceiptVersionSlice
from finishup.domain.values import (
    Frontier,
    JsonObject,
    frontier_from_json,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.domain.values import (
    JsonValue as DomainJsonValue,
)
from finishup.kernel.finding_todo import DEFAULT_FINDING_ATTEMPT_BUDGET, MAX_FINDING_ATTEMPT_BUDGET
from finishup.kernel.lineage import LineageEvaluation
from finishup.kernel.review_mode import ConversationReviewContext
from finishup.observability.logging import (
    record_classified_exception_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.observability.read_stages import read_stage
from finishup.ports.change_capture import (
    ChangeCapturePort,
    CheckWorkspaceSource,
    SnapshotBoundary,
    check_workspace_source_scope,
)
from finishup.ports.clock import ClockPort
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    McpHostProfile,
    ProjectionRenderMode,
    RepositoryPrivacyContext,
)
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.host_lineage import HostLineageRegistryPort
from finishup.ports.ids import IdPort
from finishup.ports.importer import ImportAllocation
from finishup.ports.ledger import (
    CheckAwaitingHuman,
    CheckCommitResult,
    CheckObservationsAwaited,
    FrozenCase,
)
from finishup.ports.publish_response_catalog import (
    PublishResponseCatalogPort,
    PublishResponseKey,
    StoredPublishResponse,
)
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from finishup.ports.start_catalog import SessionState, StartCatalogPort, TaskRoute, TaskRouteState
from finishup.protocol.canonical import (
    MAX_JSON_DEPTH,
    JsonValue,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import (
    SESSION_NOT_FOUND_MESSAGE,
    PublicErrorCode,
    PublicOperationError,
)
from finishup.protocol.ids import IdKind, validate_id
from finishup.protocol.models import (
    CheckAwaitingHumanModel,
    CheckInspectionModel,
    CheckRequest,
    CheckResult,
    CheckResultModel,
    CheckSuccessModel,
    DataCategory,
    OmittedContentModel,
    PublishWorkRequest,
    PublishWorkResult,
    PublishWorkResultModel,
    PublishWorkSuccessModel,
    ReceiptRequest,
    ReceiptResult,
    ReceiptResultModel,
    ReceiptSuccessModel,
    RespondRequest,
    RespondResult,
    RespondResultModel,
    RespondSuccessModel,
    StartRequest,
    StartResult,
    StartResultModel,
    StartSuccessModel,
    StatusBriefSuccessModel,
    StatusRequest,
    StatusResult,
    StatusResultModel,
    StatusSuccessModel,
    classify_result_leaf,
    public_model_to_wire,
)

__all__ = [
    "ClientProjectionContext",
    "ControlProjectionBinding",
    "ProjectionBindingFacts",
    "Application",
    "ProjectedControlBody",
    "ProjectionRenderMode",
    "ReadyApplicationFactory",
    "ServiceReadyContext",
    "UnprojectedControlBody",
    "VerificationPolicy",
    "internal_control_json",
    "resolve_client_disclosure_sink",
]

_MAX_FINDINGS_LIMIT = 10

# These families are ordinary public writes, but their catalog state must move together with the
# accepted ledger event.  The three service-owned families are intentionally kept separate: they
# are rejected by ``publish_work`` and can only be appended by the coordinator's authenticated
# service writer path.
_LINEAGE_PUBLIC_LIFECYCLE_FAMILIES = frozenset(
    {
        "delegation_cancelled",
        "child_accepted",
        "child_rejected",
        "child_written_off",
        "work_closed",
        "work_cancelled",
        "work_written_off",
    }
)


def _declared_input_paths(request: PublishWorkRequest) -> tuple[str, ...]:
    """The ``role: input`` file and directory values a batch's obligations declare (#1118)."""

    values: list[str] = []
    for draft in request.event_drafts:
        if not isinstance(draft, Mapping):
            continue
        schema = draft.get("schema")
        if not isinstance(schema, Mapping) or schema.get("name") != "obligation_published":
            continue
        version = schema.get("version")
        try:
            payload = decode_payload(
                EventSchema("obligation_published", cast(str, version)),
                cast(DomainJsonValue, draft.get("payload")),
            )
        except (TypeError, ValueError):
            continue
        if type(payload) is not ObligationPublishedPayload:
            continue
        values.extend(
            item.value
            for item in payload.requested_items
            if item.role is RequestedItemRole.INPUT
            and item.item_kind in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}
        )
    return tuple(dict.fromkeys(values))


def _lineage_publication_payloads(request: PublishWorkRequest) -> tuple[object, ...]:
    """Decode lifecycle drafts after request validation using the frozen domain registry.

    ``PublishWorkRequest`` deliberately keeps drafts as canonical JSON so the ordinary publish
    path can preserve its existing request identity.  This small service-side projection extracts
    only the lineage payloads needed to update the catalog; it never stores or logs the submitted
    title, description, or other event content.
    """

    payloads: list[object] = []
    for draft in request.event_drafts:
        if not isinstance(draft, Mapping):
            continue
        schema = draft.get("schema")
        if not isinstance(schema, Mapping):
            continue
        name = schema.get("name")
        version = schema.get("version")
        if type(name) is not str or type(version) is not str:
            continue
        if name not in _LINEAGE_PUBLIC_LIFECYCLE_FAMILIES | LINEAGE_SERVICE_STAMPED_FAMILIES:
            continue
        try:
            payloads.append(
                decode_payload(
                    EventSchema(name, version),
                    cast(DomainJsonValue, draft.get("payload")),
                )
            )
        except (TypeError, ValueError) as exc:
            # The normal publish validator runs before this helper.  Reaching this branch means
            # the caller supplied a hand-built model that bypassed that contract, so expose one
            # stable request error instead of leaking parser details.
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The lineage lifecycle event is invalid.",
                False,
                safe_details={"reason_code": "lineage_event_invalid"},
            ) from exc
    return tuple(payloads)


async def _refuse_superseded_coordination(
    projects: ProjectApplication,
    project_id_value: str,
    membership_generation: int,
    message: str,
) -> None:
    """Refuse a coordination binding whose project generation can never be current again.

    Opt-out, opt-in, revoke, consent revocation, link, unlink, and dissolve each retire the old
    generation.  Reauthorizing it is impossible by design, so ``coordination_admission_required``
    would send the caller after authority that cannot exist.  This refusal names the stale
    generation instead; its directive points at a check, which records the delivered context as
    history, and at the current successor detection when the overlap still applies.
    """

    try:
        superseded = await coordination_generation_superseded(
            projects, project_id_value, membership_generation
        )
    except (CoordinationError, ValueError):
        return
    if superseded:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            message,
            False,
            safe_details={"reason_code": "coordination_generation_superseded"},
        )


def _coordination_publication_payloads(
    request: PublishWorkRequest,
) -> tuple[CoordinationDispositionRecordedPayload, ...]:
    """Decode only typed coordination dispositions from an ordinary publish request."""

    payloads: list[CoordinationDispositionRecordedPayload] = []
    for draft in request.event_drafts:
        if not isinstance(draft, Mapping):
            continue
        schema = draft.get("schema")
        if not isinstance(schema, Mapping):
            continue
        if schema.get("name") != "coordination_disposition_recorded":
            continue
        try:
            payload = decode_payload(
                EventSchema(
                    cast(str, schema.get("name")),
                    cast(str, schema.get("version")),
                ),
                cast(DomainJsonValue, draft.get("payload")),
            )
        except (TypeError, ValueError) as exc:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination disposition is invalid.",
                False,
                safe_details={"reason_code": "coordination_disposition_invalid"},
            ) from exc
        if type(payload) is not CoordinationDispositionRecordedPayload:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination disposition is invalid.",
                False,
                safe_details={"reason_code": "coordination_disposition_invalid"},
            )
        payloads.append(payload)
    return tuple(payloads)


def _coordination_declaration_payloads(
    request: PublishWorkRequest,
) -> tuple[CoordinationObligationDeclaredPayload, ...]:
    """Decode explicit coordination bindings from an ordinary agent publication."""

    payloads: list[CoordinationObligationDeclaredPayload] = []
    for draft in request.event_drafts:
        if not isinstance(draft, Mapping):
            continue
        schema = draft.get("schema")
        if not isinstance(schema, Mapping):
            continue
        if schema.get("name") != "coordination_obligation_declared":
            continue
        try:
            payload = decode_payload(
                EventSchema(
                    cast(str, schema.get("name")),
                    cast(str, schema.get("version")),
                ),
                cast(DomainJsonValue, draft.get("payload")),
            )
        except (TypeError, ValueError) as exc:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination declaration is invalid.",
                False,
                safe_details={"reason_code": "coordination_declaration_invalid"},
            ) from exc
        if type(payload) is not CoordinationObligationDeclaredPayload:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination declaration is invalid.",
                False,
                safe_details={"reason_code": "coordination_declaration_invalid"},
            )
        payloads.append(payload)
    return tuple(payloads)


@dataclass(frozen=True, slots=True)
class ClientProjectionContext:
    """Trusted service-side facts used to choose one ordinary disclosure sink."""

    client_kind: ControlClientKind
    render_mode: ProjectionRenderMode
    output_is_controlling_tty: bool
    # Set only by the service after it consumed a human-control owner-view grant for this exact
    # receipt call (``service/owner_view.py``); never derived from a client assertion.
    owner_view: bool = False

    def __post_init__(self) -> None:
        if type(self.client_kind) is not ControlClientKind:
            raise TypeError("projection_client_kind_invalid")
        if type(self.render_mode) is not ProjectionRenderMode:
            raise TypeError("projection_render_mode_invalid")
        if type(self.output_is_controlling_tty) is not bool:
            raise TypeError("projection_tty_fact_invalid")
        if type(self.owner_view) is not bool:
            raise TypeError("projection_owner_view_invalid")

    @classmethod
    def fail_safe(cls, client_kind: ControlClientKind) -> ClientProjectionContext:
        """Construct the non-human default used when presentation facts are absent."""

        return cls(
            client_kind=client_kind,
            render_mode=ProjectionRenderMode.MACHINE_READABLE,
            output_is_controlling_tty=False,
        )


@dataclass(frozen=True, slots=True, repr=False)
class ControlProjectionBinding:
    """Trusted control and route facts bound to one ordinary-client projection."""

    rpc_id: str
    method: ControlMethod
    service_instance_id: str
    service_generation: int
    original_request_id: str | None
    route_identity_digest: str | None
    control_request_canonical: bytes
    repository_privacy_commitment: str | None = None

    def __post_init__(self) -> None:
        validate_id(IdKind.CONTROL_RPC, self.rpc_id)
        if type(self.method) is not ControlMethod:
            raise TypeError("projection_method_invalid")
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        if type(self.service_generation) is not int or self.service_generation <= 0:
            raise ValueError("projection_service_generation_invalid")
        if self.original_request_id is not None:
            validate_id(IdKind.REQUEST, self.original_request_id)
        if self.route_identity_digest is not None:
            validate_sha256_digest(self.route_identity_digest)
        if self.repository_privacy_commitment is not None:
            validate_commitment(self.repository_privacy_commitment)
        if type(self.control_request_canonical) is not bytes or not self.control_request_canonical:
            raise TypeError("projection_control_request_invalid")
        try:
            wire = strict_json_parse(self.control_request_canonical)
            if canonical_encode(wire) != self.control_request_canonical or not isinstance(
                wire, Mapping
            ):
                raise ValueError("projection_control_request_invalid")
            source = cast(Mapping[str, JsonValue], wire)
            if (
                source.get("rpc_id") != self.rpc_id
                or source.get("method") != self.method.value
                or source.get("service_instance_id") != self.service_instance_id
                or source.get("service_generation") != str(self.service_generation)
            ):
                raise ValueError("projection_control_request_mismatch")
        except (TypeError, ValueError) as exc:
            raise ValueError("projection_control_request_invalid") from exc

    def __repr__(self) -> str:
        return "ControlProjectionBinding(<redacted>)"


@dataclass(frozen=True, slots=True)
class ProjectionBindingFacts:
    """Route authority resolved inside the ready application for daemon binding."""

    original_request_id: str | None
    route_identity_digest: str | None

    def __post_init__(self) -> None:
        if self.original_request_id is not None:
            validate_id(IdKind.REQUEST, self.original_request_id)
        if self.route_identity_digest is not None:
            validate_sha256_digest(self.route_identity_digest)


def resolve_client_disclosure_sink(context: ClientProjectionContext) -> LocalDisclosureSink:
    """Resolve the sole ordinary-client sink without accepting a caller-named sink."""

    if type(context) is not ClientProjectionContext:
        raise TypeError("projection_context_invalid")
    # Every surface is agent-facing by default (ADR-009 round 3). A terminal, a human-readable
    # rendering or a client kind is a presentation fact an agent can produce (a pseudo-terminal
    # satisfies every terminal test), so none of them selects the owner's view. Only a grant the
    # human-control ceremony minted after reauthentication does, and only for a CLI or terminal
    # interface receipt call that the service matched to it.
    if context.owner_view and context.client_kind in {ControlClientKind.CLI, ControlClientKind.UI}:
        return LocalDisclosureSink.LOCAL_HUMAN_VIEW
    return LocalDisclosureSink.AGENT_CONTEXT


@dataclass(frozen=True, slots=True)
class VerificationPolicy:
    """Immutable application snapshot of the two verification configuration choices."""

    semantic: Literal["disabled", "optional", "required"] = "optional"
    max_findings: int = 3
    # Issue #905: the owner's per-item review-round budget (``kernel/finding_todo.py``).
    finding_attempt_budget: int = DEFAULT_FINDING_ATTEMPT_BUDGET

    def __post_init__(self) -> None:
        if self.semantic not in {"disabled", "optional", "required"}:
            raise ValueError("verification_semantic_invalid")
        if type(self.max_findings) is not int or not 1 <= self.max_findings <= _MAX_FINDINGS_LIMIT:
            raise ValueError("verification_max_findings_invalid")
        if (
            type(self.finding_attempt_budget) is not int
            or not 1 <= self.finding_attempt_budget <= MAX_FINDING_ATTEMPT_BUDGET
        ):
            raise ValueError("verification_finding_attempt_budget_invalid")

    @property
    def default_check_mode(
        self,
    ) -> Literal["deterministic_only", "semantic_if_configured", "semantic_required"]:
        """Map the configured AI-powered review default to the frozen check-request vocabulary."""

        if self.semantic == "disabled":
            return "deterministic_only"
        if self.semantic == "required":
            return "semantic_required"
        return "semantic_if_configured"


type ProjectedControlBody = (
    StartResult
    | PublishWorkResult
    | CheckResult
    | RespondResult
    | StatusResult
    | ReceiptResult
    | JsonObject
)


# These imports intentionally follow ``VerificationPolicy``: check.py consumes that immutable
# configuration type, while the facade owns the closed union of all use-case internal results.
from finishup.application.check import (  # noqa: E402
    check_awaiting_human_json,
    check_internal_json,
)
from finishup.application.check_inspection import (  # noqa: E402
    CheckInspection,
    check_inspection_json,
)
from finishup.application.import_review import (  # noqa: E402
    ImportCodexJsonlRequest,
    ImportReportInternal,
    ReviewInternal,
    ReviewRequest,
    execute_import_codex_jsonl,
    execute_review,
    import_request_from_control,
)
from finishup.application.publish_work import (  # noqa: E402
    PublishWorkInternalResult,
    execute_publish_work,
)
from finishup.application.receipt import ReceiptInternalResult, execute_receipt  # noqa: E402
from finishup.application.respond import RespondInternalResult, execute_respond  # noqa: E402
from finishup.application.start import (  # noqa: E402
    StartInternalResult,
    execute_start,
    start_projection_wire,
)
from finishup.application.status import StatusInternalResult, execute_status  # noqa: E402
from finishup.domain.findings import (  # noqa: E402
    Finding,
)

type UnprojectedControlBody = (
    StartInternalResult
    | PublishWorkInternalResult
    | CheckCommitResult
    | CheckAwaitingHuman
    | CheckInspection
    | RespondInternalResult
    | StatusInternalResult
    | ReceiptInternalResult
    | ImportReportInternal
    | ReviewInternal
    | JsonObject
    | DeliverySource
)


class _SemanticEvaluator(Protocol):
    def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: TaskRuntime | None = None,
        lineage_evaluation: LineageEvaluation | None = None,
        require_complete_specification: bool = False,
    ) -> Awaitable[object]: ...

    # ``final_review`` (issue #976) is optional on this port: ``evaluate_semantic_check`` passes
    # it only to evaluators whose signature declares it, so older doubles stay assignable.


type _ScopeResolver = Callable[
    [ControlProjectionBinding, Mapping[str, JsonValue]], AuthorizationScope
]
type _ReceiptVersions = Callable[[TaskRuntime], ReceiptVersionSlice]
type _SupportHandler = Callable[..., Awaitable[JsonObject]]


def _accepts_keyword(function: object, name: str) -> bool:
    try:
        parameters = inspect.signature(cast(Callable[..., object], function)).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == name or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _empty_support_handlers() -> Mapping[ControlMethod, _SupportHandler]:
    return {}


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
_STRUCTURAL_SUPPORT_METHODS = frozenset(
    {
        ControlMethod.IMPORT_CODEX_JSONL,
        ControlMethod.PRIVACY_GET_SETUP,
        ControlMethod.PRIVACY_GET_EFFECTIVE,
        ControlMethod.PRIVACY_PROPOSE_POLICY,
        ControlMethod.PRIVACY_TIGHTEN_POLICY,
        ControlMethod.BACKUP_PREVIEW,
        ControlMethod.BACKUP_EXECUTE,
        ControlMethod.OBSERVATION_INGEST,
        ControlMethod.OBSERVATION_STATUS,
        ControlMethod.OBSERVATION_PAUSE,
        ControlMethod.OBSERVATION_RESUME,
        ControlMethod.OBSERVATION_REVOKE,
        ControlMethod.PROJECT,
    }
)
_PATH_BEARING_SUPPORT_METHODS = frozenset(
    {
        ControlMethod.RESTORE_PREVIEW,
        ControlMethod.RESTORE_EXECUTE,
        ControlMethod.MIGRATE_PREVIEW,
        ControlMethod.MIGRATE_EXECUTE,
        ControlMethod.INTEGRATION_PREVIEW,
        ControlMethod.INTEGRATION_EXECUTE,
    }
)


def _pointer_matches(pointer: str, pattern: str) -> bool:
    actual = pointer.removeprefix("/").split("/")
    expected = pattern.removeprefix("/").split("/")
    return len(actual) == len(expected) and all(
        wanted == "*" or wanted == found for found, wanted in zip(actual, expected, strict=True)
    )


def _classify_support_result_leaf(
    method: ControlMethod,
    source: Mapping[str, JsonValue],
    pointer: str,
) -> Literal["public_structural"] | DataCategory:
    """Closed support classification; unknown methods and fields fail closed as content."""

    if method is ControlMethod.REVIEW:
        prefix = "/check_result"
        if pointer.startswith(f"{prefix}/"):
            nested = source.get("check_result")
            if not isinstance(nested, Mapping):
                raise TypeError("review_internal_check_invalid")
            return classify_result_leaf(
                ControlMethod.CHECK.value,
                cast(Mapping[str, JsonValue], nested),
                pointer.removeprefix(prefix),
            )
        return "public_structural"
    if method in _STRUCTURAL_SUPPORT_METHODS:
        return "public_structural"
    if method in _PATH_BEARING_SUPPORT_METHODS:
        if any(
            _pointer_matches(pointer, pattern)
            for pattern in (
                "/changed_files/*",
                "/file_changes/*/relative_path",
                "/file_states/*/relative_path",
            )
        ):
            return DataCategory.COMMAND_METADATA
        return "public_structural"
    return DataCategory.COMMAND_METADATA


def _internal_json(result: UnprojectedControlBody) -> dict[str, JsonValue]:
    if type(result) is DeliverySource:
        return _internal_json(result.result)
    if type(result) is StartInternalResult:
        return result.as_wire()
    if type(result) is PublishWorkInternalResult:
        return result.as_json()
    if type(result) is CheckCommitResult:
        return dict(check_internal_json(result).items())
    if type(result) is CheckAwaitingHuman:
        return dict(check_awaiting_human_json(result).items())
    if type(result) is CheckInspection:
        return check_inspection_json(result)
    if type(result) is RespondInternalResult:
        return result.as_json()
    if type(result) is StatusInternalResult:
        return result.as_json()
    if type(result) is ReceiptInternalResult:
        return result.as_json()
    if type(result) is ImportReportInternal:
        return dict(result.as_json().items())
    if type(result) is ReviewInternal:
        return dict(result.as_json().items())
    if type(result) is JsonObject:
        return dict(result.items())
    raise TypeError("unprojected_control_body_invalid")


def _request_body_detail(binding: ControlProjectionBinding) -> JsonValue:
    """The ``detail`` the projected result's own request named, if any (#1244, D13)."""

    try:
        control = strict_json_parse(binding.control_request_canonical)
    except (TypeError, ValueError):
        return None
    body = control.get("body") if isinstance(control, dict) else None
    return body.get("detail") if isinstance(body, dict) else None


def _projection_json(result: UnprojectedControlBody) -> dict[str, JsonValue]:
    """Return the client-facing pre-privacy shape without changing durable result bytes."""

    if type(result) is StartInternalResult:
        return start_projection_wire(result)
    return _internal_json(result)


def internal_control_json(result: UnprojectedControlBody) -> dict[str, JsonValue]:
    """Public alias for reading an unprojected body's structural facts.

    The daemon needs the committed frontier when response projection has failed and there is no
    success body left to read it from. That is a legitimate structural read, not a projection, so
    it does not go through the privacy path.
    """

    return _internal_json(result)


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _leaves(value: JsonValue, pointer: str = "") -> tuple[tuple[str, JsonValue], ...]:
    rows: list[tuple[str, JsonValue]] = []
    if isinstance(value, Mapping):
        for key, item in cast(Mapping[str, JsonValue], value).items():
            rows.extend(_leaves(item, f"{pointer}/{_escape_pointer(key)}"))
    elif type(value) in {tuple, list}:
        for index, item in enumerate(cast(tuple[JsonValue, ...] | list[JsonValue], value)):
            rows.extend(_leaves(item, f"{pointer}/{index}"))
    else:
        rows.append((pointer, value))
    return tuple(rows)


def _segments(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise ValueError("projection_pointer_invalid")
    return tuple(
        segment.replace("~1", "/").replace("~0", "~")
        for segment in pointer.removeprefix("/").split("/")
    )


def _replace_pointer(root: JsonValue, pointer: str, replacement: JsonValue) -> JsonValue:
    # Every failure here is a bounded ValueError. This runs inside the post-commit projection
    # window, where an unexpected exception (KeyError from a missing key, IndexError or
    # ValueError from a non-numeric array segment) is reclassified as response_projection_failed
    # and turns a durable success into an apparent failure the caller cannot replay away.
    parts = _segments(pointer)

    def replace_at(value: JsonValue, depth: int) -> JsonValue:
        if depth == len(parts):
            return replacement
        part = parts[depth]
        if isinstance(value, Mapping):
            source = dict(cast(Mapping[str, JsonValue], value))
            if part not in source:
                raise ValueError("projection_pointer_unresolved")
            source[part] = replace_at(source[part], depth + 1)
            return source
        if type(value) in {tuple, list}:
            source_list = list(cast(tuple[JsonValue, ...] | list[JsonValue], value))
            if not part.isascii() or not part.isdecimal() or (part != "0" and part.startswith("0")):
                raise ValueError("projection_pointer_unresolved")
            index = int(part)
            if index >= len(source_list):
                raise ValueError("projection_pointer_unresolved")
            source_list[index] = replace_at(source_list[index], depth + 1)
            return tuple(source_list)
        raise ValueError("projection_pointer_invalid")

    return replace_at(root, 0)


def _frontier_for_projection(source: Mapping[str, JsonValue]) -> Frontier:
    raw = source.get("subject_frontier", source.get("frontier"))
    if raw is None:
        raise ValueError("projection_frontier_missing")
    return frontier_from_json(raw)


def _plain_nested_mappings(value: JsonValue, depth: int = 0) -> JsonValue:
    """Rebuild every nested mapping as a built-in ``dict``, changing nothing else.

    The public result models are ``strict=True``. Strict pydantic accepts only a real ``dict`` (or
    an instance of the target model) where a nested model is declared, and the internal results
    carry nested entries as ``JsonObject`` — a genuine ``Mapping``, but not a ``dict``. Top-level
    fields survived because they are scalars; every nested collection element was rejected.

    The conversion is structural only: scalars are returned untouched, key order is preserved, no
    key is added or dropped, and sequence containers keep their own type so the closed models'
    established list-to-tuple adaptation still sees what it saw before. A genuinely invalid shape
    therefore still fails validation, at the same pointer, with the same error.

    Depth is bounded exactly as ``finishup.protocol.canonical`` bounds it: a *container* node at
    ``MAX_JSON_DEPTH`` is rejected, counting the root container as depth zero. Anything the internal
    results were legitimately built under therefore normalizes, and a structure this boundary would
    admit but canonicalization would not cannot slip through — a pathological one degrades to a
    named rejection inside the projection window rather than recursing without limit.
    """

    if isinstance(value, Mapping):
        if depth >= MAX_JSON_DEPTH:
            raise ValueError("projection_value_too_deep")
        source = cast(Mapping[str, JsonValue], value)
        return {key: _plain_nested_mappings(item, depth + 1) for key, item in source.items()}
    if type(value) is tuple:
        if depth >= MAX_JSON_DEPTH:
            raise ValueError("projection_value_too_deep")
        return tuple(_plain_nested_mappings(item, depth + 1) for item in value)
    if type(value) is list:
        if depth >= MAX_JSON_DEPTH:
            raise ValueError("projection_value_too_deep")
        return [_plain_nested_mappings(item, depth + 1) for item in cast(list[JsonValue], value)]
    return value


def _public_model(method: ControlMethod, value: Mapping[str, JsonValue]) -> ProjectedControlBody:
    """Validate and normalize one projected success body for its public result model."""

    # CHECK has two success shapes. The nonterminal one carries no verdict or coverage, so it
    # cannot validate against the terminal model; pick the branch the body actually declares.
    check_success: type[BaseModel] = (
        CheckAwaitingHumanModel
        if value.get("state") in {"awaiting_human", "awaiting_input"}
        else CheckInspectionModel
        if value.get("state") == "inspected"
        else CheckSuccessModel
    )
    # Issue #1084: a ``detail: brief`` status body is its own closed subset shape.
    status_success: type[BaseModel] = (
        StatusBriefSuccessModel if value.get("detail") == "brief" else StatusSuccessModel
    )
    model: tuple[type[BaseModel], type[BaseModel]] | None = {
        ControlMethod.START: (StartSuccessModel, StartResultModel),
        ControlMethod.PUBLISH_WORK: (PublishWorkSuccessModel, PublishWorkResultModel),
        ControlMethod.CHECK: (check_success, CheckResultModel),
        ControlMethod.RESPOND: (RespondSuccessModel, RespondResultModel),
        ControlMethod.STATUS: (status_success, StatusResultModel),
        ControlMethod.RECEIPT: (ReceiptSuccessModel, ReceiptResultModel),
    }.get(method)
    if model is None:
        return JsonObject(value)
    success_type, result_type = model
    success = success_type.model_validate(_plain_nested_mappings(value))
    # Every closed result model that declares ``optional_non_null_fields`` requires those leaves
    # to be entirely omitted when absent, never present as an explicit null. A dump that keeps
    # defaulted Nones reintroduces the null after a clean internal body survived disclosure and
    # crashes the reflexive re-validation below (publish ``summary``, respond reason/waiver
    # fields, status obligation ``acceptance_criteria``, structural subject-state digests).
    # ``exclude_unset`` drops only fields that were never populated, so required nullable keys
    # that were set to null (status ``revision_event_id``) still project. Respond and publish
    # also exclude any remaining nulls as belt-and-suspenders for their internal builders.
    exclude_none = method in {ControlMethod.RESPOND, ControlMethod.PUBLISH_WORK}
    return result_type.model_validate(
        success.model_dump(
            mode="json",
            by_alias=True,
            exclude_unset=True,
            exclude_none=exclude_none,
        )
    )


@dataclass(frozen=True, slots=True)
class Application:
    """Ready-only facade with one sink-independent workflow and one disclosure boundary."""

    start_catalog: StartCatalogPort
    publish_responses: PublishResponseCatalogPort
    runtime: BundleRuntimePort
    clock: ClockPort
    ids: IdPort
    verification_policy: VerificationPolicy
    privacy: PrivacyCoordinator
    status_cursor_key: bytes
    waiver_policy_digest: str
    semantic_evaluator: _SemanticEvaluator
    disclosure_scope_for: _ScopeResolver
    receipt_version_resolver: _ReceiptVersions
    waiver_authorizer: Callable[[RespondRequest], bool]
    import_publication_authorizer: Callable[[object], bool]
    profile: RuntimeProfile
    policy_packs: tuple[str, ...]
    version_manifest: Mapping[str, JsonValue]
    support_handlers: Mapping[ControlMethod, _SupportHandler] = field(
        default_factory=_empty_support_handlers
    )
    verification_supervisor: ObservationVerificationSupervisor | None = None
    connected_provider_ids: tuple[str, ...] = ()
    provider_credential_connected: bool = False
    # Structural presence of the declared fallback endpoint's credential (#582); never readiness.
    fallback_credential_connected: bool = False
    semantic_ready: bool = False
    observation_sweep: Callable[[], Awaitable[object]] | None = field(
        default=None, repr=False, compare=False
    )
    coordination_sweep: Callable[[], Awaitable[object]] | None = field(
        default=None, repr=False, compare=False
    )
    ready_recommendation_refresh: Callable[[], Awaitable[object]] | None = field(
        default=None, repr=False, compare=False
    )
    # Off-hook observation-advice AI-powered review attempts (#619); stopped with the verification
    # supervisor so no provider attempt outlives this generation's privacy coordinator.
    advice_semantic_supervisor: ObservationAdviceSemanticSupervisor | None = field(
        default=None, repr=False, compare=False
    )
    # The sweeper owns a worker pool of its own; this generation's close is the only place that
    # can release it, so it travels with the sweep it belongs to.
    observation_sweep_close: Callable[[], None] | None = field(
        default=None, repr=False, compare=False
    )
    # One task-local admission hook runs after a new CHECK hits a retryable capture barrier and
    # before its single freeze retry. It may retire unfinished native-content handoffs whose local
    # authority has changed; it never touches captured history or the ledger projection.
    reconcile_observation_capture: Callable[[TaskRuntime], Awaitable[None]] | None = field(
        default=None, repr=False, compare=False
    )
    # Historical loss is reconciled before a new CHECK freezes; already-frozen
    # operations retain their original case. This hook may append loss evidence.
    reconcile_observation_losses: Callable[[TaskRuntime], Awaitable[None]] | None = field(
        default=None, repr=False, compare=False
    )
    enforce_repository_identity: bool = True
    # The lineage coordinator is optional for pre-0004 test/catalog compositions.  READY
    # production composition supplies the SQLite-backed instance so status and start share one
    # authority.
    lineage: LineageCoordinator | None = field(default=None, repr=False, compare=False)
    project_application: ProjectApplication | None = field(default=None, repr=False, compare=False)
    host_lineage_registry: HostLineageRegistryPort | None = field(
        default=None, repr=False, compare=False
    )
    # Read-only repository access for the check-time change (ADR-031). ``None`` in embedded and
    # test compositions: tasks then record no start base and checks bind no workspace source.
    change_capture: ChangeCapturePort | None = field(default=None, repr=False, compare=False)
    # #1118 unit 1: what a task-input snapshot may read for one repository task now, or ``None``
    # when the policy admits no root or review carries no inputs. ``None`` in embedded and test
    # compositions: tasks then keep no snapshots and checks label outside inputs as current.
    input_snapshot_scope: (
        Callable[[RepositoryPrivacyContext, str], Awaitable[InputSnapshotScope | None]] | None
    ) = field(default=None, repr=False, compare=False)
    # ADR-049: reads the owner's conversation setting and review availability for one task.
    # ``None`` in embedded and test compositions: checks keep the released behaviour.
    conversation_review_reader: (
        Callable[[TaskRuntime], Awaitable[ConversationReviewContext | None]] | None
    ) = field(default=None, repr=False, compare=False)
    # #1244 (D12): delivered page sets, in this process's memory only (never disk or ledger).
    delivery_pages: DeliveryPageStore = field(
        default_factory=DeliveryPageStore, repr=False, compare=False
    )
    _lineage_publish_lock: asyncio.Lock = field(init=False, repr=False, compare=False)
    # One ready service owns one runtime cache.  Serialize start admission so two concurrent
    # route rotations for the same bundle cannot race the runtime's single-writer lease while the
    # catalog still admits both request identities atomically.
    _start_lock: asyncio.Lock = field(init=False, repr=False, compare=False)
    _close_lock: asyncio.Lock = field(init=False, repr=False, compare=False)
    _close_task: asyncio.Task[None] | None = field(
        init=False, default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "_lineage_publish_lock", asyncio.Lock())
        object.__setattr__(self, "_start_lock", asyncio.Lock())
        object.__setattr__(self, "_close_lock", asyncio.Lock())
        if type(self.connected_provider_ids) is not tuple or any(
            type(item) is not str for item in self.connected_provider_ids
        ):
            raise TypeError("connected_provider_ids_invalid")
        if type(self.provider_credential_connected) is not bool:
            raise TypeError("provider_credential_connected_invalid")
        if type(self.semantic_ready) is not bool:
            raise TypeError("semantic_ready_invalid")
        if self.observation_sweep is not None and not callable(self.observation_sweep):
            raise TypeError("observation_sweep_invalid")
        if self.coordination_sweep is not None and not callable(self.coordination_sweep):
            raise TypeError("coordination_sweep_invalid")
        if self.ready_recommendation_refresh is not None and not callable(
            self.ready_recommendation_refresh
        ):
            raise TypeError("ready_recommendation_refresh_invalid")
        if self.observation_sweep_close is not None and not callable(self.observation_sweep_close):
            raise TypeError("observation_sweep_close_invalid")
        if self.reconcile_observation_losses is not None and not callable(
            self.reconcile_observation_losses
        ):
            raise TypeError("reconcile_observation_losses_invalid")
        if self.reconcile_observation_capture is not None and not callable(
            self.reconcile_observation_capture
        ):
            raise TypeError("reconcile_observation_capture_invalid")
        if type(self.enforce_repository_identity) is not bool:
            raise TypeError("repository_identity_enforcement_invalid")
        # Readiness may never outrun the resolved binding. A connected provider that is not the
        # configured one leaves dispatch on the credential-unavailable path, so a readiness flag
        # set without it would report ready while every check reports unavailable.
        if self.semantic_ready and not self.provider_credential_connected:
            raise ValueError("semantic_ready_without_connected_provider_credential")

    async def verify_recovery_candidate(self) -> tuple[int, int, int]:
        """Replay every active task and authenticate its currently present objects.

        The method returns structural counts only.  It is invoked before a recovered passphrase
        marker is selected, so any corrupt route, ledger chain, projection, or object keeps the
        prior encrypted authority active.
        """

        list_routes = getattr(self.start_catalog, "recovery_routes", None)
        if not callable(list_routes):
            raise TypeError("recovery_catalog_verifier_unavailable")
        routes = await cast(Callable[[], Awaitable[tuple[TaskRoute, ...]]], list_routes)()
        if type(routes) is not tuple:
            raise TypeError("recovery_catalog_verifier_invalid")
        active_routes = 0
        replayed_events = 0
        verified_objects = 0
        for route in routes:
            if type(route) is not TaskRoute:
                raise TypeError("recovery_catalog_verifier_invalid")
            if route.state is not TaskRouteState.ACTIVE:
                continue
            runtime = await self.runtime.route(
                RouteCommand(
                    session_id=route.session_id,
                    writer_id=None,
                    access=RouteAccess.PAYLOAD_READ,
                    required_capabilities=frozenset(
                        {
                            RuntimeCapability.STRUCTURAL_READ,
                            RuntimeCapability.PAYLOAD_READ,
                        }
                    ),
                )
            )
            try:
                frontier = await runtime.ledger.load_frontier()
                observed = 0
                async for _record in runtime.ledger.load_events(route.session_id):
                    observed += 1
                if observed > frontier.sequence:
                    raise ValueError("recovery_ledger_frontier_invalid")
                verify_objects = getattr(runtime.ledger, "verify_recovery_objects", None)
                if not callable(verify_objects):
                    raise TypeError("recovery_object_verifier_unavailable")
                object_count = await cast(Callable[[], Awaitable[int]], verify_objects)()
                if type(object_count) is not int or object_count < 0:
                    raise TypeError("recovery_object_verifier_invalid")
                active_routes += 1
                replayed_events += observed
                verified_objects += object_count
            finally:
                await self.runtime.release(runtime)
        return active_routes, replayed_events, verified_objects

    async def start(
        self,
        request: StartRequest,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> StartInternalResult:
        # Delegate/self-register requests use a parent session as their authority but do not pass
        # through the start-catalog route transition that rotates or renews an existing session.
        # Touch that lease before executing the lineage operation so an active parent cannot be
        # declared contact-lost while its child is being provisioned.  Ordinary resume/create
        # requests are renewed by the catalog reservation itself; attach has no pre-existing child
        # session to renew.
        if request.mode == "delegate":
            await self._renew_activity_session(request.session_id, request)
        elif request.parent_session_id is not None:
            await self._renew_activity_session(request.parent_session_id, request)
        statement_paths = statement_input_paths(request.task_statement)

        async def capture(task: TaskRuntime, key: str, boundary: SnapshotBoundary) -> None:
            await self._capture_inputs(
                task, key, statement_paths, boundary, repository_privacy_context, request.request_id
            )

        async with self._start_lock:
            # A public lifecycle append and its catalog mirror share the lineage publication
            # lock.  Parent-authorized starts take that same lock and reconcile any event that
            # survived an append-before-sync crash before admission, so a stale OPEN projection
            # cannot mint a child after the parent ledger already closed its work.  Attach has no
            # parent admission and remains allowed to continue an already-minted child.
            parent_admission = request.mode == "delegate" or request.parent_session_id is not None
            if parent_admission:
                async with self._lineage_publish_lock:
                    await self.reconcile_lineage_publications()
                    result = await execute_start(
                        self,  # pyright: ignore[reportArgumentType]
                        request,
                        repository_privacy_commitment=(
                            None
                            if repository_privacy_context is None
                            else repository_privacy_context.commitment
                        ),
                        input_capture=capture,
                    )
            else:
                result = await execute_start(
                    self,  # pyright: ignore[reportArgumentType]
                    request,
                    repository_privacy_commitment=(
                        None
                        if repository_privacy_context is None
                        else repository_privacy_context.commitment
                    ),
                    input_capture=capture,
                )
            await self._maybe_birth_implicit_repository_project(repository_privacy_context)
            await self._record_task_change_base(result, repository_privacy_context)
            return result

    async def _capture_inputs(
        self,
        task: TaskRuntime,
        key: str,
        values: tuple[str, ...],
        boundary: SnapshotBoundary,
        repository_privacy_context: RepositoryPrivacyContext | None,
        request_id: str,
    ) -> None:
        """Keep copies of the outside inputs ``values`` names at boundary ``key`` (#1118 unit 1).

        Called inside the admitting operation, before its event is appended. Best effort: a task
        without a copy still runs; its checks label outside inputs as current bytes and disclose
        ``task_input_baseline_unavailable``. A scope that is denied or unavailable still reserves
        ``key`` as a gap, reading nothing, so a recovered attempt never captures later bytes.
        """

        source = self.input_snapshot_scope
        if source is None or not any(value.startswith("/") for value in values):
            return
        scope = None
        if repository_privacy_context is not None:
            try:
                scope = await source(repository_privacy_context, task.task_id)
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="start",
                    operation="input_snapshot_scope_failed",
                    request_id=request_id,
                )
        await record_input_snapshot(
            runtime=task,
            key=key,
            values=values,
            scope=scope,
            boundary=boundary,
            clock=self.clock,
            request_id=request_id,
        )

    async def _record_task_change_base(
        self,
        result: StartInternalResult,
        repository_privacy_context: RepositoryPrivacyContext | None,
    ) -> None:
        """Keep HEAD as the new task's change base before its creator gets the result (ADR-031).

        Only a start that created the task records a base, so the base is the repository state
        before the task's first edit or commit. Attach and resume never record one: a base taken
        later would silently hide the commits made in between. Best effort; a task without a base
        still gets a check-time change, shown against HEAD with that limit disclosed.
        """

        port = self.change_capture
        locator = (
            None
            if repository_privacy_context is None
            else repository_privacy_context.workspace_locator
        )
        if port is None or locator is None or result.outcome not in {"created", "delegated"}:
            return
        try:
            runtime = await self.runtime.route(
                RouteCommand(
                    result.session_id,
                    result.writer_id,
                    RouteAccess.WRITE,
                    frozenset({RuntimeCapability.WRITE}),
                )
            )
        except Exception as exc:
            # The start itself succeeded; a missing base must never turn it into a failure.
            record_unexpected_exception_without_raising(
                exc,
                component="start",
                operation="task_change_base_route_failed",
                request_id=result.request_id,
            )
            return
        try:
            await record_task_change_base(
                runtime=runtime,
                port=port,
                workspace=locator.path,
                clock=self.clock,
                request_id=result.request_id,
            )
        finally:
            await self.runtime.release(runtime)

    async def _maybe_birth_implicit_repository_project(
        self, repository_privacy_context: RepositoryPrivacyContext | None
    ) -> None:
        """Create the implicit repository project when a second task is actually live.

        Repository identity is trusted control context, so a public workspace or external
        selector cannot trigger discovery.  The project is born only after the completed start
        route is visible as ``active`` with an active session; an initializing or contact-lost task
        never counts.  The catalog's ensure operation is idempotent across replays.
        """

        if repository_privacy_context is None:
            return
        list_tasks = getattr(self.start_catalog, "list_repository_task_ids", None)
        task_route = getattr(self.start_catalog, "task_route", None)
        task_session_state = getattr(self.start_catalog, "task_session_state", None)
        ensure_project = getattr(self.start_catalog, "ensure_repository_project", None)
        grouping_enabled = getattr(self.start_catalog, "repository_auto_grouping_enabled", None)
        ensure_if_enabled = getattr(
            self.start_catalog, "ensure_repository_project_if_auto_grouping_enabled", None
        )
        if not all(
            callable(item)
            for item in (
                list_tasks,
                task_route,
                task_session_state,
                ensure_project,
                grouping_enabled,
            )
        ):
            return
        repository = repository_privacy_context.commitment
        task_ids = await cast(Callable[[str], Awaitable[tuple[str, ...]]], list_tasks)(repository)
        live = 0
        for task_id in task_ids:
            route = await cast(Callable[[str], Awaitable[TaskRoute | None]], task_route)(task_id)
            if route is None or route.state is not TaskRouteState.ACTIVE:
                continue
            if getattr(route, "work_state", WorkState.OPEN) is not WorkState.OPEN:
                continue
            state = await cast(Callable[[str], Awaitable[SessionState | None]], task_session_state)(
                route.session_id
            )
            if state is not None and state.health is SessionHealth.ACTIVE:
                live += 1
                if live >= 2:
                    enabled = await cast(Callable[[str], Awaitable[bool]], grouping_enabled)(
                        repository
                    )
                    if type(enabled) is not bool or not enabled:
                        return
                    if callable(ensure_if_enabled):
                        await cast(Callable[[str], Awaitable[object]], ensure_if_enabled)(
                            repository
                        )
                    else:
                        # Older test doubles may only implement the original ensure operation;
                        # the preference recheck above still prevents disabled implicit birth.
                        await cast(Callable[[str], Awaitable[object]], ensure_project)(repository)
                    return

    async def _renew_activity_session(
        self,
        session_id: str | None,
        request: object,
    ) -> None:
        """Renew contact for an authenticated workflow request, including routed status reads.

        The start catalog owns session leases; the lineage projection separately retains recovery
        deadlines. Renew both under the recovery fence so a formerly lost session cannot carry a
        stale abandonment deadline into its next contact-loss window.
        """

        async with self._lineage_publish_lock:
            await self._renew_activity_session_locked(session_id, request)

    async def _renew_activity_session_locked(self, session_id: str | None, request: object) -> None:
        if type(session_id) is not str:
            return
        binding = await self.start_catalog.session_binding(session_id)
        if binding is None or binding.session_id != session_id:
            return
        request_writer_id = getattr(request, "writer_id", None)
        if type(request_writer_id) is str and request_writer_id != binding.writer_id:
            return
        record = getattr(self.start_catalog, "record_session_state", None)
        if callable(record):
            actor = getattr(getattr(request, "actor", None), "actor_id", None)
            await cast(Callable[..., Awaitable[object]], record)(
                binding.task_id,
                session_id,
                health=SessionHealth.ACTIVE,
                changed_at=self.clock.now_utc(),
                lease_expires_at=None,
                actor_id=actor if type(actor) is str else None,
            )
        lineage = self.lineage
        if lineage is None:
            return
        snapshot = await lineage.store.get_task(binding.task_id)
        if snapshot is None or (
            snapshot.active_session_id == session_id
            and snapshot.session_health is SessionHealth.ACTIVE
            and snapshot.contact_lost_at is None
            and snapshot.abandonment_deadline is None
        ):
            return
        if snapshot.active_session_id not in {None, session_id}:
            return
        await lineage.store.save_task(
            replace(
                snapshot,
                active_session_id=session_id,
                session_health=SessionHealth.ACTIVE,
                contact_lost_at=None,
                abandonment_deadline=None,
                lineage_authority_revision=snapshot.lineage_authority_revision + 1,
            )
        )

    async def lineage_status(
        self,
        task_id: str,
        requester_session_id: str,
        *,
        at_frontier: int | None = None,
    ) -> LineageStatus:
        """Return one authenticated, one-level lineage projection.

        Structural lineage is scoped to the requesting task session.  The optional frontier is a
        freshness assertion for callers that already read a task ledger; catalog lifecycle state
        is still the authority and no child payload is loaded here.
        """

        if self.lineage is None:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "The lineage service is temporarily unavailable.",
                True,
                safe_details={"reason_code": "lineage_service_unavailable"},
            )
        if type(at_frontier) not in {int, type(None)} or (
            type(at_frontier) is int and at_frontier < 0
        ):
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The lineage frontier is invalid.",
                False,
            )
        try:
            bound_task = await self.lineage.store.get_session_task(requester_session_id)
        except (TypeError, ValueError) as exc:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The lineage session is invalid.",
                False,
            ) from exc
        try:
            requested_task_id = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The lineage task is invalid.",
                False,
            ) from exc
        if bound_task != requested_task_id:
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT,
                "The lineage session is not authorized for this task.",
                False,
                safe_details={"reason_code": "lineage_session_scope"},
            )
        return await self.lineage.status(task_id)

    async def recover_lineage(self) -> tuple[tuple[object, ...], tuple[object, ...]]:
        """Run one bounded recovery sweep for delegation operations and task sessions.

        The daemon may invoke this from its existing service sweep.  Recovery is explicit and
        clock-injected: an expired lease becomes ``contact_lost`` first, and only a later sweep
        after the configured window changes open work to ``abandoned``.  No receipt or status read
        calls this method implicitly.
        """

        async with self._start_lock, self._lineage_publish_lock:
            return await self._recover_lineage_locked()

    async def _recover_lineage_locked(self) -> tuple[tuple[object, ...], tuple[object, ...]]:
        if self.lineage is None:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "The lineage service is temporarily unavailable.",
                True,
                safe_details={"reason_code": "lineage_service_unavailable"},
            )
        # Ledger lifecycle events are the evidence of an accepted public write.  Reconcile that
        # evidence before expiring leases so a restart cannot strand a catalog projection merely
        # because the session stopped heartbeating while the process was down.
        await self.reconcile_lineage_publications()
        # A parent waiting on a host-declared child operation emits no host event of its own for
        # the whole run.  Hold those sessions before expiring leases, so a native subagent that
        # outlasts the lease and recovery window cannot abandon the parent it reports back to.
        clock = self.clock
        catalog = self.start_catalog

        async def hold_lease(task_id: str, session_id: str, lease_until: datetime) -> bool:
            return await extend_session_lease(
                catalog,
                clock,
                task_id=task_id,
                session_id=session_id,
                lease_until=lease_until,
            )

        await self.lineage.hold_in_flight_contact(hold_lease)
        store = self.lineage.store
        expired: tuple[SessionState, ...] = ()
        expire = getattr(store, "expire_session_leases", None)
        if callable(expire):
            expired = tuple(await cast(Callable[[], Awaitable[tuple[SessionState, ...]]], expire)())
            for state in expired:
                await self.lineage.mark_contact_lost(session_id=state.session_id)
        reclaimed = tuple(await self.lineage.recover_delegations())
        operations: list[object] = []
        for operation in reclaimed:
            try:
                operations.append(await recover_delegation(self, operation))
            except PublicOperationError as exc:
                # A parent that is still ended or a bundle temporarily held by another worker
                # remains pending under its durable lease.  The next periodic sweep reclaims and
                # retries it; unrelated tasks continue through this recovery turn.
                if not exc.retryable:
                    continue
            except (OSError, TimeoutError):
                # Environmental bundle/key availability is likewise retryable at this boundary.
                continue

        async def record_abandonment(
            snapshot: LineageSnapshot, reason: str, deadline: datetime
        ) -> None:
            await append_abandonment(self, snapshot, reason, deadline)

        abandoned = tuple(await self.lineage.recover_abandoned(record_abandonment))
        return tuple(operations), (*expired, *abandoned)

    async def reconcile_lineage_publications(self) -> tuple[int, int]:
        """Repair catalog lifecycle rows from events that survived an append-before-sync crash.

        Ledger append and catalog projection are separate durable stores.  The normal publish path
        mirrors them immediately, but a process can terminate between those commits.  On the next
        ready generation, read-capable routes provide the authenticated ledger bytes and this
        method reapplies only registered lineage lifecycle payloads through idempotent recovery
        transitions.  It deliberately scans historical session ids through the current task
        runtime, so a reattach before recovery does not hide the old event.

        The return value is structural only: ``(events_scanned, events_reconciled)``.
        """

        lineage = self.lineage
        if lineage is None:
            return 0, 0
        list_tasks = getattr(lineage.store, "list_tasks", None)
        task_route = getattr(self.start_catalog, "task_route", None)
        task_sessions = getattr(self.start_catalog, "task_session_states", None)
        if not callable(list_tasks) or not callable(task_route):
            return 0, 0
        snapshots = await cast(Callable[[], Awaitable[tuple[object, ...]]], list_tasks)()
        scanned = 0
        reconciled = 0
        for snapshot in snapshots:
            if not isinstance(snapshot, LineageSnapshot):
                # ``list_tasks`` is a typed lineage-store seam; keep malformed compatibility
                # doubles from becoming a user-visible maintenance crash.
                continue
            task_id = snapshot.task_id
            route = await cast(Callable[[str], Awaitable[TaskRoute | None]], task_route)(task_id)
            if route is None or route.state is TaskRouteState.QUARANTINED:
                continue
            try:
                if route.state is TaskRouteState.INITIALIZING:
                    # A completed, never-attached delegation has an inert bundle, not a public
                    # route. Its service event still fences parent cancel/write-off after a
                    # crash between the abandonment append and catalog projection.
                    runtime = await lineage_recovery_runtime(self, task_id)
                else:
                    runtime = await self.runtime.route(
                        RouteCommand(
                            session_id=route.session_id,
                            writer_id=None,
                            access=RouteAccess.PAYLOAD_READ,
                            required_capabilities=frozenset(
                                {RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}
                            ),
                        )
                    )
            except PublicOperationError as exc:
                # Another ready request may briefly own the bundle opener, or the generation may
                # be closing.  Leave that route for the next bounded sweep; hard storage errors
                # still surface so the daemon's recovery diagnostics remain honest.
                if exc.retryable:
                    continue
                raise
            try:
                session_ids: tuple[str, ...] = (route.session_id,)
                if callable(task_sessions):
                    states = await cast(
                        Callable[[str], Awaitable[tuple[SessionState, ...]]], task_sessions
                    )(task_id)
                    session_ids = tuple(
                        sorted({route.session_id, *(state.session_id for state in states)})
                    )
                seen_events: set[str] = set()
                for session_id in session_ids:
                    async for record in runtime.ledger.load_events(session_id):
                        if not isinstance(record, AcceptedEvent) or str(record.task_id) != task_id:
                            continue
                        event_id = str(record.event_id)
                        if event_id in seen_events:
                            continue
                        seen_events.add(event_id)
                        payload = record.payload
                        if not isinstance(
                            payload,
                            (
                                ChildAcceptedPayload,
                                ChildRejectedPayload,
                                ChildWrittenOffPayload,
                                DelegationCancelledPayload,
                                WorkClosedPayload,
                                WorkCancelledPayload,
                                WorkWrittenOffPayload,
                                WorkAbandonedPayload,
                            ),
                        ):
                            continue
                        scanned += 1
                        if isinstance(payload, ChildAcceptedPayload):
                            await lineage.reconcile_child_acceptance(
                                parent_task_id=task_id,
                                child_task_id=str(payload.child_task_id),
                                target=LineageAcceptance.ACCEPTED,
                            )
                        elif isinstance(payload, ChildRejectedPayload):
                            await lineage.reconcile_child_acceptance(
                                parent_task_id=task_id,
                                child_task_id=str(payload.child_task_id),
                                target=LineageAcceptance.REJECTED,
                            )
                        elif isinstance(payload, ChildWrittenOffPayload):
                            await lineage.reconcile_child_work(
                                parent_task_id=task_id,
                                child_task_id=str(payload.child_task_id),
                                target=WorkState.WRITTEN_OFF,
                            )
                        elif isinstance(payload, DelegationCancelledPayload):
                            await lineage.reconcile_child_work(
                                parent_task_id=task_id,
                                child_task_id=str(payload.child_task_id),
                                target=WorkState.CANCELLED,
                            )
                        elif isinstance(payload, WorkClosedPayload):
                            await lineage.reconcile_owned_work(
                                task_id=task_id, target=WorkState.CLOSED
                            )
                        elif isinstance(payload, WorkCancelledPayload):
                            await lineage.reconcile_owned_work(
                                task_id=task_id, target=WorkState.CANCELLED
                            )
                        elif isinstance(payload, WorkAbandonedPayload):
                            await lineage.reconcile_owned_work(
                                task_id=task_id, target=WorkState.ABANDONED
                            )
                        else:
                            await lineage.reconcile_owned_work(
                                task_id=task_id, target=WorkState.WRITTEN_OFF
                            )
                        reconciled += 1
            finally:
                await self.runtime.release(runtime)
        return scanned, reconciled

    async def _sync_lineage_publication(
        self,
        request: PublishWorkRequest,
        payloads: tuple[object, ...],
    ) -> None:
        """Apply accepted public lifecycle events to the authoritative lineage catalog."""

        if not payloads:
            return
        lineage = self.lineage
        if lineage is None:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "The lineage service is temporarily unavailable.",
                True,
                safe_details={"reason_code": "lineage_service_unavailable"},
            )
        for payload in payloads:
            if isinstance(payload, ChildAcceptedPayload):
                await lineage.accept_child(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                )
            elif isinstance(payload, ChildRejectedPayload):
                await lineage.reject_child(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                )
            elif isinstance(payload, ChildWrittenOffPayload):
                await lineage.write_off_child(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                )
            elif isinstance(payload, DelegationCancelledPayload):
                await lineage.cancel_child(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                )
            elif isinstance(payload, WorkClosedPayload):
                await lineage.close_work(session_id=request.session_id)
            elif isinstance(payload, WorkCancelledPayload):
                await lineage.cancel_work(session_id=request.session_id)
            elif isinstance(payload, WorkWrittenOffPayload):
                await lineage.write_off_work(session_id=request.session_id)
            else:
                # Service-only families are rejected before append by ``prepare_publication``.  A
                # defensive branch keeps a future family from silently bypassing catalog state.
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The lineage lifecycle event is not publicly writable.",
                    False,
                    safe_details={"reason_code": "event_family_not_admitted"},
                )

    async def _validate_lineage_publication(
        self,
        request: PublishWorkRequest,
        payloads: tuple[object, ...],
    ) -> None:
        """Validate public lifecycle authority before the ledger append.

        Catalog transitions are applied after the append so a successful publication has one
        durable operation identity.  This read-only pass closes the reverse failure window: a
        stale parent or terminal child is refused before an event can be accepted without its
        matching lineage projection.  Service-stamped families remain the responsibility of the
        ordinary publish admission guard and are intentionally skipped here.
        """

        lineage = self.lineage
        if not payloads:
            return
        if lineage is None:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "The lineage service is temporarily unavailable.",
                True,
                safe_details={"reason_code": "lineage_service_unavailable"},
            )
        # A single append is atomic in the task ledger, so it must describe at most one terminal
        # decision for each relationship/task.  Without this preflight, a batch containing
        # ``work_closed`` followed by ``work_cancelled`` would append both events and only mirror
        # the first catalog transition; every retry would then be unable to reconcile the second.
        acceptance_targets: dict[str, LineageAcceptance] = {}
        work_targets: dict[str, WorkState] = {}
        for payload in payloads:
            if isinstance(payload, ChildAcceptedPayload):
                key = str(payload.child_task_id)
                target = LineageAcceptance.ACCEPTED
                previous = acceptance_targets.setdefault(key, target)
                if previous is not target:
                    raise PublicOperationError(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The child lifecycle batch contains conflicting transitions.",
                        False,
                        safe_details={"reason_code": "lineage_transition_conflict"},
                    )
            elif isinstance(payload, ChildRejectedPayload):
                key = str(payload.child_task_id)
                target = LineageAcceptance.REJECTED
                previous = acceptance_targets.setdefault(key, target)
                if previous is not target:
                    raise PublicOperationError(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The child lifecycle batch contains conflicting transitions.",
                        False,
                        safe_details={"reason_code": "lineage_transition_conflict"},
                    )
            elif isinstance(payload, ChildWrittenOffPayload):
                key = str(payload.child_task_id)
                target = WorkState.WRITTEN_OFF
                previous = work_targets.setdefault(key, target)
                if previous is not target:
                    raise PublicOperationError(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The child lifecycle batch contains conflicting transitions.",
                        False,
                        safe_details={"reason_code": "lineage_transition_conflict"},
                    )
            elif isinstance(payload, DelegationCancelledPayload):
                key = str(payload.child_task_id)
                target = WorkState.CANCELLED
                previous = work_targets.setdefault(key, target)
                if previous is not target:
                    raise PublicOperationError(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The child lifecycle batch contains conflicting transitions.",
                        False,
                        safe_details={"reason_code": "lineage_transition_conflict"},
                    )
            elif isinstance(payload, WorkClosedPayload):
                key = request.session_id
                target = WorkState.CLOSED
                previous = work_targets.setdefault(key, target)
                if previous is not target:
                    raise PublicOperationError(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The task lifecycle batch contains conflicting transitions.",
                        False,
                        safe_details={"reason_code": "lineage_transition_conflict"},
                    )
            elif isinstance(payload, WorkCancelledPayload):
                key = request.session_id
                target = WorkState.CANCELLED
                previous = work_targets.setdefault(key, target)
                if previous is not target:
                    raise PublicOperationError(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The task lifecycle batch contains conflicting transitions.",
                        False,
                        safe_details={"reason_code": "lineage_transition_conflict"},
                    )
            elif isinstance(payload, WorkWrittenOffPayload):
                key = request.session_id
                target = WorkState.WRITTEN_OFF
                previous = work_targets.setdefault(key, target)
                if previous is not target:
                    raise PublicOperationError(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The task lifecycle batch contains conflicting transitions.",
                        False,
                        safe_details={"reason_code": "lineage_transition_conflict"},
                    )
        for payload in payloads:
            if isinstance(payload, ChildAcceptedPayload):
                await lineage.validate_acceptance_transition(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                    target=LineageAcceptance.ACCEPTED,
                )
            elif isinstance(payload, ChildRejectedPayload):
                await lineage.validate_acceptance_transition(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                    target=LineageAcceptance.REJECTED,
                )
            elif isinstance(payload, ChildWrittenOffPayload):
                await lineage.validate_child_work_transition(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                    target=WorkState.WRITTEN_OFF,
                )
            elif isinstance(payload, DelegationCancelledPayload):
                await lineage.validate_child_work_transition(
                    parent_session_id=request.session_id,
                    child_task_id=str(payload.child_task_id),
                    target=WorkState.CANCELLED,
                )
            elif isinstance(payload, WorkClosedPayload):
                await lineage.validate_owned_work_transition(
                    session_id=request.session_id,
                    target=WorkState.CLOSED,
                )
            elif isinstance(payload, WorkCancelledPayload):
                await lineage.validate_owned_work_transition(
                    session_id=request.session_id,
                    target=WorkState.CANCELLED,
                )
            elif isinstance(payload, WorkWrittenOffPayload):
                await lineage.validate_owned_work_transition(
                    session_id=request.session_id,
                    target=WorkState.WRITTEN_OFF,
                )
            elif isinstance(
                payload,
                (DelegationDeclaredPayload, ChildDependenciesRecordedPayload, WorkAbandonedPayload),
            ):
                continue
            else:
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The lineage lifecycle event is not publicly writable.",
                    False,
                    safe_details={"reason_code": "event_family_not_admitted"},
                )

    async def _require_repository_route(
        self,
        request: object,
        repository_privacy_context: RepositoryPrivacyContext | None,
    ) -> None:
        """Fence every task workflow to the trusted repository on its active route."""

        if not self.enforce_repository_identity:
            return

        session_id = getattr(request, "session_id", None)
        if type(session_id) is not str:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The task request is invalid.",
                False,
            )
        route = await self.start_catalog.resolve_route(session_id)
        request_task_id = getattr(request, "task_id", None)
        if route is None:
            binding = await self.start_catalog.session_binding(session_id)
            if binding is not None and binding.session_id != session_id:
                raise PublicOperationError(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    (
                        "The requested session was replaced. Continue with session_id "
                        f"{binding.session_id} and writer_id {binding.writer_id}."
                    ),
                    False,
                    safe_details={
                        "reason_code": "session_superseded",
                        "task_id": binding.task_id,
                        "session_id": binding.session_id,
                        "writer_id": binding.writer_id,
                    },
                )
            raise PublicOperationError(
                PublicErrorCode.SESSION_NOT_FOUND,
                SESSION_NOT_FOUND_MESSAGE,
                False,
            )
        if request_task_id is not None and request_task_id != route.task_id:
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT,
                "The requested task attachment conflicts.",
                False,
            )
        expected = route.repository_privacy_commitment
        actual = (
            None if repository_privacy_context is None else repository_privacy_context.commitment
        )
        if expected is None or actual is None or not hmac.compare_digest(expected, actual):
            # The closed reason lets a caller tell "this connection carried no
            # repository locator" from "the locator resolved to a different
            # repository than the route" without disclosing either commitment
            # (issue #578): a hook status probe sent without a workspace was
            # otherwise indistinguishable from a replaced session.
            if repository_privacy_context is None:
                message = (
                    "The request has no repository context. Run from the original workspace "
                    "directory or reconnect the host to that workspace before retrying."
                )
            else:
                message = (
                    "The request's repository context does not match the task attachment "
                    f"(current identity kind: {repository_privacy_context.identity_kind}). "
                    "Run from the original workspace directory or reconnect the host to that "
                    "workspace before retrying. If the original directory is unavailable, "
                    "this operation cannot be inspected through the task workflow."
                )
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT,
                message,
                False,
                safe_details={
                    "reason_code": (
                        "repository_identity_required"
                        if actual is None
                        else "repository_identity_mismatch"
                    )
                },
            )

    async def publish_work(
        self,
        request: PublishWorkRequest,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> PublishWorkInternalResult | PublishWorkResult:
        await self._require_repository_route(request, repository_privacy_context)
        await self._renew_activity_session(request.session_id, request)
        payloads = _lineage_publication_payloads(request)
        coordination_declarations = _coordination_declaration_payloads(request)
        coordination_payloads = _coordination_publication_payloads(request)
        await self._validate_coordination_declarations(request, coordination_declarations)
        await self._validate_coordination_publications(request, coordination_payloads)
        declared = _declared_input_paths(request)

        async def capture(task: TaskRuntime) -> None:
            # #1118 unit 1: an outside input the task first names in this batch is copied inside
            # the publication, before its append, keyed by this request.
            await self._capture_inputs(
                task,
                request.request_id,
                declared,
                "admission_time",
                repository_privacy_context,
                request.request_id,
            )

        if any(
            isinstance(
                item,
                (DelegationDeclaredPayload, ChildDependenciesRecordedPayload, WorkAbandonedPayload),
            )
            for item in payloads
        ):
            # Service-stamped facts are never admitted through the ordinary client writer, even
            # when a caller presents a harness/service-looking actor.  Their authenticated writer
            # paths are delegation and manifest/lease recovery respectively.
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The lineage lifecycle event is not publicly writable.",
                False,
                safe_details={"reason_code": "event_family_not_admitted"},
            )
        if payloads:
            # Serialize lifecycle validation, ledger append/replay, and catalog reconciliation in
            # this service generation.  A retry after a post-append failure can then reapply the
            # same idempotent transition without a second concurrent writer changing its target.
            async with self._lineage_publish_lock:
                # A service abandonment (or earlier public lifecycle append) can be durable
                # while its catalog projection is still open after an interrupted save. Repair
                # that evidence before admitting another terminal event on this or a child task.
                await self.reconcile_lineage_publications()
                await self._validate_lineage_publication(request, payloads)
                result = await execute_publish_work(self, request, capture)  # pyright: ignore[reportArgumentType]
                # Dry-run is explicitly non-mutating.  A real accepted or replayed publication is
                # idempotently mirrored into catalog state after the ledger append succeeds.
                if not (
                    isinstance(result, PublishWorkResultModel)
                    and getattr(result.root, "outcome", None) == "dry_run"
                ):
                    await self._sync_lineage_publication(request, payloads)
                    await self._sweep_project_coordination(result)
                    await self._apply_coordination_dispositions(coordination_payloads)
                return result
        result = await execute_publish_work(self, request, capture)  # pyright: ignore[reportArgumentType]
        await self._sweep_project_coordination(result)
        if not (
            isinstance(result, PublishWorkResultModel)
            and getattr(result.root, "outcome", None) == "dry_run"
        ):
            await self._apply_coordination_dispositions(coordination_payloads)
        return result

    async def _sweep_project_coordination(self, result: object) -> None:
        """Run the ready project's durable overlap sweep after an accepted publish.

        Coordination is a secondary, idempotent projection of the already durable ledger append.
        A detector/runtime failure therefore cannot turn a successful ``publish_work`` into a
        false write failure; the next public publish or explicit maintenance sweep retries the
        same generation-bound pair delivery through the durable store.  The failure is still
        recorded as one bounded diagnostic (exception-class token and correlation id only), so a
        sweep that stops producing detections is visible to an operator instead of silent.
        Per-task input failures are isolated inside the sweep itself and become coverage rows.
        """

        if not isinstance(result, PublishWorkInternalResult):
            return

        project_application = self.project_application
        if project_application is None:
            return
        coordinator = getattr(project_application, "coordination_runtime", None)
        sweep = getattr(coordinator, "sweep", None)
        if not callable(sweep):
            return
        try:
            pending = sweep(task_id=result.task_id)
            if inspect.isawaitable(pending):
                await pending
        except Exception as exc:
            # The ledger result is already committed.  Delivery rows and the next sweep provide
            # crash/restart recovery; no user-controlled content is attached to this diagnostic
            # boundary.
            record_classified_exception_without_raising(
                exc,
                component="application.service",
                operation="project_coordination_sweep",
                request_id=result.request_id,
            )
            return

    async def _validate_coordination_publications(
        self,
        request: PublishWorkRequest,
        payloads: tuple[CoordinationDispositionRecordedPayload, ...],
    ) -> None:
        """Fence typed dispositions to the current recipient route and durable obligation."""

        if not payloads:
            return
        projects = self.project_application
        if projects is None:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination disposition is unavailable.",
                False,
                safe_details={"reason_code": "coordination_runtime_unavailable"},
            )
        resolve_route = getattr(self.start_catalog, "resolve_route", None)
        if not callable(resolve_route):
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination disposition is unavailable.",
                False,
                safe_details={"reason_code": "coordination_route_unavailable"},
            )
        route = await cast(Callable[[str], Awaitable[TaskRoute | None]], resolve_route)(
            request.session_id
        )
        coordinator = getattr(projects, "coordination_runtime", None)
        detector = getattr(coordinator, "detector", None)
        store = getattr(detector, "store", None)
        if route is None or store is None:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination disposition is unavailable.",
                False,
                safe_details={"reason_code": "coordination_runtime_unavailable"},
            )
        for payload in payloads:
            if payload.recipient_task_id != route.task_id:
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination disposition is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_recipient_mismatch"},
                )
            detection = await store.get_detection(str(payload.detection_id))
            state = await store.obligation(str(payload.detection_id), route.task_id)
            if (
                detection is None
                or detection.project_id != str(payload.project_id)
                or detection.membership_generation != payload.membership_generation
                or route.task_id not in {detection.left_task_id, detection.right_task_id}
                or state is None
                or not state.declared
                or state.obligation_id != str(payload.obligation_id)
            ):
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination disposition is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_obligation_mismatch"},
                )
            # A superseded generation can never be admitted again.  Say so precisely instead of
            # asking for authority review: the available action is a check, which records the
            # context as history, or a declaration against a current successor detection (#842).
            await _refuse_superseded_coordination(
                projects,
                str(payload.project_id),
                payload.membership_generation,
                "The coordination disposition names a superseded project generation.",
            )
            provenance = await projects.catalog.task_source_provenance(route.task_id)
            if provenance is None or provenance.workspace_ref_commitment is None:
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination disposition is unavailable.",
                    False,
                    safe_details={"reason_code": "coordination_source_unavailable"},
                )
            try:
                await projects.admit(
                    source_task_id=route.task_id,
                    source_workspace_commitment=provenance.workspace_ref_commitment,
                    project=str(payload.project_id),
                    expected_generation=payload.membership_generation,
                )
            except (CoordinationError, ValueError) as exc:
                # The generation may have advanced after the check above; recheck so a race
                # still reports the reason the caller can act on.
                await _refuse_superseded_coordination(
                    projects,
                    str(payload.project_id),
                    payload.membership_generation,
                    "The coordination disposition names a superseded project generation.",
                )
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination disposition is unavailable.",
                    False,
                    safe_details={"reason_code": "coordination_admission_required"},
                ) from exc

            # Evidence references are proof links, not caller assertions.  Require each to be
            # present in the recipient ledger before accepting the disposition.
            task_runtime = await self.runtime.route(
                RouteCommand(
                    route.session_id,
                    None,
                    RouteAccess.PAYLOAD_READ,
                    frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
                )
            )
            try:
                found: set[str] = set()
                context_digest: str | None = None
                context_sequence = 0
                async for record in task_runtime.ledger.load_events(task_runtime.session_id):
                    if type(record) is not AcceptedEvent or record.payload is None:
                        continue
                    if isinstance(record.payload, EvidenceRecordedPayload):
                        found.add(str(record.payload.evidence_id))
                    elif isinstance(record.payload, ResultRecordedPayload):
                        found.add(str(record.payload.result_id))
                    elif isinstance(record.payload, CoordinationContextRecordedPayload):
                        context = record.payload
                        if (
                            context.detection_id == payload.detection_id
                            and context.project_id == payload.project_id
                            and context.membership_generation == payload.membership_generation
                            and context.recipient_task_id == payload.recipient_task_id
                            and record.ledger.ingestion_sequence > context_sequence
                        ):
                            context_digest = context.context_digest
                            context_sequence = record.ledger.ingestion_sequence
                if payload.context_digest is not None and payload.context_digest != context_digest:
                    raise PublicOperationError(
                        PublicErrorCode.INVALID_REQUEST,
                        "The coordination disposition is invalid.",
                        False,
                        safe_details={"reason_code": "coordination_detection_mismatch"},
                    )
                if any(str(ref) not in found for ref in payload.evidence_refs):
                    raise PublicOperationError(
                        PublicErrorCode.INVALID_REQUEST,
                        "The coordination disposition is invalid.",
                        False,
                        safe_details={"reason_code": "coordination_evidence_missing"},
                    )
            finally:
                await self.runtime.release(task_runtime)

    async def _validate_coordination_declarations(
        self,
        request: PublishWorkRequest,
        payloads: tuple[CoordinationObligationDeclaredPayload, ...],
    ) -> None:
        """Validate an ordinary declaration against the exact frozen detection pair.

        The declaration event is authored by the recipient task through ``publish_work``.  The
        service checks the current route, the existing open obligation, both source workspaces,
        and the generation-bound project admission before the event is appended.  The subsequent
        project sweep consumes the accepted event from the recipient ledger; no service writer
        synthesizes a declaration on the caller's behalf.
        """

        if not payloads:
            return
        projects = self.project_application
        if projects is None:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination declaration is unavailable.",
                False,
                safe_details={"reason_code": "coordination_runtime_unavailable"},
            )
        resolve_route = getattr(self.start_catalog, "resolve_route", None)
        if not callable(resolve_route):
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination declaration is unavailable.",
                False,
                safe_details={"reason_code": "coordination_route_unavailable"},
            )
        route = await cast(Callable[[str], Awaitable[TaskRoute | None]], resolve_route)(
            request.session_id
        )
        coordinator = getattr(projects, "coordination_runtime", None)
        detector = getattr(coordinator, "detector", None)
        store = getattr(detector, "store", None)
        inputs = getattr(coordinator, "inputs", None)
        if route is None or store is None or inputs is None:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination declaration is unavailable.",
                False,
                safe_details={"reason_code": "coordination_runtime_unavailable"},
            )
        owns_obligation = getattr(inputs, "owns_obligation", None)
        input_for = getattr(inputs, "input_for", None)
        participants_for = getattr(store, "participants", None)
        detection_for = getattr(store, "get_detection", None)
        if (
            not callable(owns_obligation)
            or not callable(input_for)
            or not callable(participants_for)
            or not callable(detection_for)
        ):
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The coordination declaration is unavailable.",
                False,
                safe_details={"reason_code": "coordination_runtime_unavailable"},
            )
        seen_bindings: dict[tuple[str, str, int], str] = {}
        for payload in payloads:
            if str(payload.recipient_task_id) != route.task_id:
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination declaration is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_recipient_mismatch"},
                )
            binding_key = (
                str(payload.detection_id),
                str(payload.recipient_task_id),
                payload.membership_generation,
            )
            prior_binding = seen_bindings.get(binding_key)
            if prior_binding is not None and prior_binding != str(payload.obligation_id):
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination declaration is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_obligation_conflict"},
                )
            seen_bindings[binding_key] = str(payload.obligation_id)
            current_input = await cast(Callable[[str, str], Awaitable[object | None]], input_for)(
                route.task_id, str(payload.project_id)
            )
            existing_declarations = (
                ()
                if current_input is None
                else getattr(current_input, "coordination_declarations", ())
            )
            for existing in cast(
                tuple[CoordinationObligationDeclaredPayload, ...], existing_declarations
            ):
                if (
                    existing.detection_id == payload.detection_id
                    and existing.recipient_task_id == payload.recipient_task_id
                    and existing.membership_generation == payload.membership_generation
                    and existing.obligation_id != payload.obligation_id
                ):
                    raise PublicOperationError(
                        PublicErrorCode.INVALID_REQUEST,
                        "The coordination declaration is invalid.",
                        False,
                        safe_details={"reason_code": "coordination_obligation_conflict"},
                    )
            detection = await cast(Callable[[str], Awaitable[object | None]], detection_for)(
                str(payload.detection_id)
            )
            if (
                detection is None
                or getattr(detection, "project_id", None) != str(payload.project_id)
                or getattr(detection, "membership_generation", None)
                != payload.membership_generation
                or route.task_id
                not in {
                    getattr(detection, "left_task_id", None),
                    getattr(detection, "right_task_id", None),
                }
            ):
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination declaration is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_detection_mismatch"},
                )
            owns = cast(
                Callable[[str, str], Awaitable[object]],
                owns_obligation,
            )(route.task_id, str(payload.obligation_id))
            if inspect.isawaitable(owns):
                owns_result = await owns
            else:
                owns_result = owns
            if owns_result is not True:
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination declaration is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_obligation_mismatch"},
                )
            participants = cast(
                tuple[CoordinationParticipant, CoordinationParticipant] | None,
                await cast(Callable[[str], Awaitable[object | None]], participants_for)(
                    str(payload.detection_id)
                ),
            )
            if (
                type(participants) is not tuple
                or len(participants) != 2
                or any(type(item) is not CoordinationParticipant for item in participants)
            ):
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination declaration is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_participants_unavailable"},
                )
            by_task: dict[str, CoordinationParticipant] = {
                item.task_id: item for item in participants
            }
            recipient = by_task.get(route.task_id)
            counterpart_id = next(
                (value for value in by_task if value != route.task_id),
                None,
            )
            if recipient is None or counterpart_id is None:
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination declaration is invalid.",
                    False,
                    safe_details={"reason_code": "coordination_participants_unavailable"},
                )
            counterpart = by_task[counterpart_id]
            await _refuse_superseded_coordination(
                projects,
                str(payload.project_id),
                payload.membership_generation,
                "The coordination declaration names a superseded project generation.",
            )
            recipient_workspace = recipient.workspace_commitment
            counterpart_workspace = counterpart.workspace_commitment
            recipient_repository = recipient.repository_commitment
            counterpart_repository = counterpart.repository_commitment
            cross_repository = recipient_repository != counterpart_repository
            try:
                await projects.admit(
                    source_task_id=route.task_id,
                    source_workspace_commitment=recipient_workspace,
                    project=str(payload.project_id),
                    expected_generation=payload.membership_generation,
                    cross_repository=cross_repository,
                )
                await projects.admit(
                    source_task_id=counterpart_id,
                    source_workspace_commitment=counterpart_workspace,
                    project=str(payload.project_id),
                    expected_generation=payload.membership_generation,
                    cross_repository=cross_repository,
                )
                current_route_generation = await projects.current_route_generation(route.task_id)
                counterpart_route_generation = await projects.current_route_generation(
                    counterpart_id
                )
                if (
                    current_route_generation != recipient.route_generation
                    or counterpart_route_generation != counterpart.route_generation
                ):
                    raise CoordinationError(CoordinationErrorCode.GENERATION_MISMATCH)
            except (CoordinationError, ValueError) as exc:
                await _refuse_superseded_coordination(
                    projects,
                    str(payload.project_id),
                    payload.membership_generation,
                    "The coordination declaration names a superseded project generation.",
                )
                raise PublicOperationError(
                    PublicErrorCode.INVALID_REQUEST,
                    "The coordination declaration is unavailable.",
                    False,
                    safe_details={"reason_code": "coordination_admission_required"},
                ) from exc

    async def _apply_coordination_dispositions(
        self,
        payloads: tuple[CoordinationDispositionRecordedPayload, ...],
    ) -> None:
        """Mirror accepted typed dispositions into durable coordination status state."""

        if not payloads or self.project_application is None:
            return
        coordinator = getattr(self.project_application, "coordination_runtime", None)
        detector = getattr(coordinator, "detector", None)
        disposition = getattr(detector, "disposition", None)
        if not callable(disposition):
            return
        for payload in payloads:
            result = disposition(
                str(payload.detection_id),
                str(payload.recipient_task_id),
                disposition=payload.disposition.value,
            )
            if inspect.isawaitable(result):
                await result

    def publish_response_key(
        self, result: PublishWorkInternalResult, sink: LocalDisclosureSink
    ) -> PublishResponseKey:
        if type(result) is not PublishWorkInternalResult or type(sink) is not LocalDisclosureSink:
            raise TypeError("publish_response_identity_invalid")
        return PublishResponseKey(
            result.task_id,
            result.session_id,
            result.writer_id,
            result.request_id,
            result.request_digest,
            sink,
        )

    def _decode_publish_response(
        self,
        result: PublishWorkInternalResult,
        key: PublishResponseKey,
        stored: StoredPublishResponse,
    ) -> PublishWorkResult:
        try:
            if type(stored) is not StoredPublishResponse or stored.key != key:
                raise ValueError("stored_publish_response_identity_invalid")
            source = strict_json_parse(stored.result_canonical)
            if canonical_encode(source) != stored.result_canonical or not isinstance(
                source, Mapping
            ):
                raise ValueError("stored_publish_response_canonical_invalid")
            wire = cast(Mapping[str, JsonValue], source)
            projected = PublishWorkResultModel.model_validate(wire)
            if type(projected.root) is not PublishWorkSuccessModel:
                raise ValueError("stored_publish_response_result_invalid")
            success = projected.root
            if (
                success.request_id != result.request_id
                or success.task_id != result.task_id
                or success.session_id != result.session_id
                or success.writer_id != result.writer_id
                or success.privacy_projection.sink != key.sink.value
            ):
                raise ValueError("stored_publish_response_identity_invalid")
            if any(
                event.summary is not None and not isinstance(event.summary, OmittedContentModel)
                for event in success.accepted_events
            ):
                raise ValueError("stored_publish_response_content_invalid")
            expected = result.as_json()
            actual = public_model_to_wire(projected)
            expected_facts = {name: value for name, value in expected.items() if name != "outcome"}
            actual_facts = {
                name: value
                for name, value in actual.items()
                if name not in {"outcome", "privacy_projection"}
            }
            expected_events = cast(
                tuple[Mapping[str, JsonValue], ...], expected_facts["accepted_events"]
            )
            actual_events = cast(list[Mapping[str, JsonValue]], actual_facts["accepted_events"])
            expected_facts["accepted_events"] = tuple(
                {name: value for name, value in event.items() if name != "summary"}
                for event in expected_events
            )
            actual_facts["accepted_events"] = tuple(
                {name: value for name, value in event.items() if name != "summary"}
                for event in actual_events
            )
            if canonical_encode(actual_facts) != canonical_encode(expected_facts):
                raise ValueError("stored_publish_response_facts_invalid")
            if canonical_encode(public_model_to_wire(projected)) != stored.result_canonical:
                raise ValueError("stored_publish_response_canonical_invalid")
            return projected
        except (TypeError, ValueError) as exc:
            raise PublicOperationError(
                PublicErrorCode.STORAGE_CORRUPT,
                "The stored publish response is invalid.",
                False,
            ) from exc

    async def load_publish_response(
        self, result: PublishWorkInternalResult, sink: LocalDisclosureSink
    ) -> PublishWorkResult | None:
        key = self.publish_response_key(result, sink)
        stored = await self.publish_responses.lookup(key)
        if stored is None:
            return None
        return self._decode_publish_response(result, key, stored)

    async def store_publish_response(
        self,
        result: PublishWorkInternalResult,
        sink: LocalDisclosureSink,
        projected: ProjectedControlBody,
    ) -> PublishWorkResult:
        if type(projected) is not PublishWorkResultModel:
            raise TypeError("projected_publish_response_invalid")
        if type(projected.root) is not PublishWorkSuccessModel:
            raise TypeError("projected_publish_response_invalid")
        success = projected.root
        key = self.publish_response_key(result, sink)
        wire = public_model_to_wire(projected)
        accepted = wire.get("accepted_events")
        if type(accepted) not in {tuple, list}:
            raise TypeError("projected_publish_response_invalid")
        accepted_items = cast(tuple[JsonValue, ...] | list[JsonValue], accepted)
        if any(not isinstance(item, Mapping) for item in accepted_items) or any(
            event.summary is not None and not isinstance(event.summary, OmittedContentModel)
            for event in success.accepted_events
        ):
            raise TypeError("projected_publish_response_invalid")
        canonical = canonical_encode(wire)
        candidate = StoredPublishResponse(
            key,
            canonical,
            f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        )
        self._decode_publish_response(result, key, candidate)
        winner = await run_publish_response_commit(self.publish_responses, candidate)
        return self._decode_publish_response(result, key, winner)

    async def check(
        self,
        request: CheckRequest,
        *,
        route_profile: Literal["policy", "strict"] = "policy",
        host_profile: McpHostProfile = "generic",
        repository_privacy_context: RepositoryPrivacyContext | None = None,
        observations_awaited: CheckObservationsAwaited | None = None,
    ) -> CheckCommitResult | CheckAwaitingHuman | CheckInspection:
        """Run one check; ``observations_awaited`` is the daemon's pre-gate wait (issue #1012)."""

        from finishup.application.check import execute_check

        await self._require_repository_route(request, repository_privacy_context)
        await self._renew_activity_session(request.session_id, request)
        if request.mode == "inspect":
            # ADR-047: a read. No default mode, no workspace capture, no reviewer route.
            inspection = await execute_check(self, request, route_profile=route_profile)  # pyright: ignore[reportArgumentType]
            if observations_awaited is not None and type(inspection) is CheckInspection:
                inspection = replace(inspection, observations_awaited=observations_awaited)
            return inspection
        # Resolve omitted mode via policy so recorded check events carry the resolved value.
        # Whether the caller named a mode decides whether the conversation's mode applies.
        mode_explicit = request.mode is not None
        if request.mode is None:
            request = request.model_copy(
                update={"mode": self.verification_policy.default_check_mode}
            )
        # The check-time change (ADR-031) may read only the directory this connection's own
        # locator named; the composition still requires its commitment to equal the route's.
        locator = (
            None
            if repository_privacy_context is None
            else repository_privacy_context.workspace_locator
        )
        source = (
            None
            if self.change_capture is None or locator is None or repository_privacy_context is None
            else CheckWorkspaceSource(locator.path, repository_privacy_context.commitment)
        )
        with check_workspace_source_scope(source):
            result = await execute_check(
                self,  # pyright: ignore[reportArgumentType]
                request,
                route_profile=route_profile,
                host_profile=host_profile,
                mode_explicit=mode_explicit,
            )
        if observations_awaited is not None and type(result) is CheckCommitResult:
            # Describes this call's wait only; nothing about it is recorded in the ledger.
            result = replace(result, observations_awaited=observations_awaited)
        return result

    async def respond(
        self,
        request: RespondRequest,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> RespondInternalResult:
        await self._require_repository_route(request, repository_privacy_context)
        await self._renew_activity_session(request.session_id, request)
        return await execute_respond(self, request)  # pyright: ignore[reportArgumentType]

    async def status(
        self,
        request: StatusRequest,
        *,
        route_profile: Literal["policy", "strict"] | None = None,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> StatusInternalResult:
        with read_stage("repository_route"):
            await self._require_repository_route(request, repository_privacy_context)
        with read_stage("session_renewal"):
            await self._renew_activity_session(request.session_id, request)
        if request.delivery_cursor is not None:
            raise invalid_cursor()
        result = await execute_status(
            self,  # pyright: ignore[reportArgumentType]
            request,
            route_profile=route_profile,
        )
        with read_stage("credential_state"):
            state = await self._credential_heuristic_state(repository_privacy_context)
        return result if state is None else replace(result, credential_heuristic=state)

    async def read_result_delivery(
        self,
        request: StatusRequest,
        *,
        route_profile: Literal["policy", "strict"] | None = None,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> DeliverySource:
        """Service status-cursor route, separate from typed internal status query results."""
        await self._require_repository_route(request, repository_privacy_context)
        await self._renew_activity_session(request.session_id, request)
        return await self._read_delivery(request, repository_privacy_context, route_profile)

    async def _read_delivery(
        self,
        request: StatusRequest,
        repository_privacy_context: RepositoryPrivacyContext | None,
        route_profile: Literal["policy", "strict"] | None,
    ) -> DeliverySource:
        """Re-read the source a handle names: a complete operation or a pinned status read.

        The kept page set (``delivery_pages``) supplies the original selector; after a miss the
        handle does (#1244, D12). The read also notes the current head and whether a redaction
        was recorded after the set's frontier, which alone refuses the continuation.
        """
        from finishup.application.check import Application as CheckApplication
        from finishup.application.check import replayed_check_view
        from finishup.application.receipt import read_recorded_receipt
        from finishup.ports.ledger import OperationKind, OperationState

        assert request.delivery_cursor is not None
        handle = decode_handle(request.delivery_cursor)
        kept = self.delivery_pages.get(handle.set_key, request.session_id, request.writer_id)
        method = handle.method
        selector: dict[str, JsonValue]
        if kept is not None:
            selector = dict(kept.selector)
        elif method == "status":
            selector = status_selector_from_code(handle.selector_code, handle)
        elif method == "receipt":
            selector = {
                "request_id": handle.source_request_id,
                **receipt_selector_from_code(handle.selector_code),
            }
        else:
            selector = {
                "request_id": handle.source_request_id,
                **({"detail": "brief"} if handle.selector_code == "b" else {}),
            }
        runtime = await self.runtime.route(
            RouteCommand(
                request.session_id,
                request.writer_id,
                RouteAccess.PAYLOAD_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
            )
        )
        try:
            head = await runtime.ledger.load_frontier()
            redacted = False
            if head.sequence > handle.frontier:
                async for record in runtime.ledger.load_events(
                    request.session_id, after=handle.frontier
                ):
                    if record.schema.name == "redaction_recorded":
                        redacted = True
                        break
            internal: object
            if method == "status":
                internal = None
            else:
                operation = await runtime.ledger.lookup_task_operation(
                    request.writer_id, str(selector["request_id"])
                )
                if (
                    operation is None
                    or operation.state is not OperationState.COMPLETE
                    or operation.operation_kind.value != method
                ):
                    raise invalid_cursor()
                if operation.operation_kind is OperationKind.CHECK:
                    stored = await runtime.ledger.load_check_result(
                        operation.writer_id, operation.operation_id
                    )
                    if stored is None:
                        raise invalid_cursor()
                    internal = await replayed_check_view(
                        cast(CheckApplication, self), runtime, stored, route_profile=route_profile
                    )
                else:
                    receipt_request = ReceiptRequest.model_validate(
                        {
                            **request.model_dump(
                                mode="json",
                                exclude_none=True,
                                include={"protocol_version", "schema_version", "actor", "client"},
                            ),
                            # A miss names no expected frontier; a recorded receipt is found by
                            # its own operation and never re-checks one.
                            "task_id": runtime.task_id,
                            "expected_frontier": {
                                "sequence": str(handle.frontier),
                                "head_digest": head.head_digest,
                            },
                            **selector,
                            "session_id": request.session_id,
                            "writer_id": request.writer_id,
                        }
                    )
                    internal = await read_recorded_receipt(runtime, receipt_request, operation)
        finally:
            await self.runtime.release(runtime)
        if method == "status":
            source_body = request.model_dump(
                mode="json",
                exclude_none=True,
                include={
                    "protocol_version",
                    "schema_version",
                    "actor",
                    "client",
                    "session_id",
                    "writer_id",
                },
            )
            try:
                source_request = StatusRequest.model_validate({**source_body, **selector})
            except ValueError as exc:
                # After a miss the selector is the handle's own: a mistyped id or limit is a
                # malformed handle, not a retryable read failure.
                raise invalid_cursor() from exc
            internal = await self.status(
                source_request,
                route_profile=route_profile,
                repository_privacy_context=repository_privacy_context,
            )
        return DeliverySource(
            internal,
            method,
            selector,
            handle,
            request.request_id,
            request.session_id,
            request.writer_id,
            {"sequence": str(head.sequence), "head_digest": head.head_digest},
            redacted,
        )

    async def _credential_heuristic_state(
        self, repository_privacy_context: RepositoryPrivacyContext | None
    ) -> tuple[str, str] | None:
        """The possible-credential filter state status shows before any check (issue #982).

        ``repository`` follows the current repository's own grant (owner decision, 2026-10-07);
        without a grant nothing reaches the external reviewer, so it reads ``enforced``.
        ``machine_default`` is what a repository without a grant inherits. Read-only; any read
        failure reports ``unknown`` rather than guessing. ``None`` when this application has no
        privacy support at all.
        """

        if (
            ControlMethod.PRIVACY_GET_SETUP not in self.support_handlers
            or ControlMethod.PRIVACY_GET_EFFECTIVE not in self.support_handlers
        ):
            return None

        def token(value: object) -> str:
            if value == "enforced" or value == "disabled" or value == "unknown":
                return cast(str, value)
            return "unknown"

        def state_of(policy: object) -> str:
            if not isinstance(policy, Mapping):
                return "unknown"
            value = cast(Mapping[str, object], policy).get("credential_heuristic", "enforced")
            if value == "enforced" or value == "disabled":
                return cast(str, value)
            return "unknown"

        if repository_privacy_context is not None:
            # The setup read carries the one derivation every surface shows (repository grant,
            # pending migration outcome, installation default).
            try:
                setup = await self._support(
                    ControlMethod.PRIVACY_GET_SETUP,
                    JsonObject({"schema_version": "2.0.0"}),
                    repository_privacy_context=repository_privacy_context,
                )
                pair = setup.get("credential_heuristic")
                if isinstance(pair, Mapping):
                    typed = cast(Mapping[str, object], pair)
                    return token(typed.get("repository")), token(typed.get("machine_default"))
            except Exception:  # noqa: BLE001 - status stays readable; the state is unknown
                pass
        try:
            effective = await self._support(
                ControlMethod.PRIVACY_GET_EFFECTIVE, JsonObject({"schema_version": "1.0.0"})
            )
            machine_default = state_of(effective.get("policy"))
        except Exception:  # noqa: BLE001 - status stays readable; the state is unknown
            machine_default = "unknown"
        return "unknown", machine_default

    async def receipt(
        self,
        request: ReceiptRequest,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> ReceiptInternalResult:
        await self._require_repository_route(request, repository_privacy_context)
        await self._renew_activity_session(request.session_id, request)
        return await execute_receipt(self, request)  # pyright: ignore[reportArgumentType]

    async def import_codex_jsonl(
        self,
        request: ImportCodexJsonlRequest | Mapping[str, object],
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> ImportReportInternal:
        if type(request) is not ImportCodexJsonlRequest:
            request = import_request_from_control(request)
        await self._require_repository_route(request, repository_privacy_context)
        await self._renew_activity_session(request.session_id, request)
        return await execute_import_codex_jsonl(
            self,  # pyright: ignore[reportArgumentType]
            request,
        )

    async def review(self, request: ReviewRequest) -> ReviewInternal:
        return await execute_review(self, request)  # pyright: ignore[reportArgumentType]

    async def privacy_get_setup(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        return await self._support(
            ControlMethod.PRIVACY_GET_SETUP,
            request,
            repository_privacy_context=repository_privacy_context,
        )

    async def privacy_get_effective(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        return await self._support(
            ControlMethod.PRIVACY_GET_EFFECTIVE,
            request,
            repository_privacy_context=repository_privacy_context,
        )

    async def privacy_propose_policy(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        return await self._support(
            ControlMethod.PRIVACY_PROPOSE_POLICY,
            request,
            repository_privacy_context=repository_privacy_context,
        )

    async def privacy_tighten_policy(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.PRIVACY_TIGHTEN_POLICY, request)

    async def privacy_pending_list(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.PRIVACY_PENDING_LIST, request)

    async def privacy_receipts_list(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.PRIVACY_RECEIPTS_LIST, request)

    async def privacy_receipts_get(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.PRIVACY_RECEIPTS_GET, request)

    async def backup_preview(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.BACKUP_PREVIEW, request)

    async def backup_execute(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.BACKUP_EXECUTE, request)

    async def restore_preview(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.RESTORE_PREVIEW, request)

    async def restore_execute(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.RESTORE_EXECUTE, request)

    async def migrate_preview(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.MIGRATE_PREVIEW, request)

    async def migrate_execute(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.MIGRATE_EXECUTE, request)

    async def integration_preview(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.INTEGRATION_PREVIEW, request)

    async def integration_execute(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.INTEGRATION_EXECUTE, request)

    async def observation_ingest(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.OBSERVATION_INGEST, request)

    async def observation_status(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.OBSERVATION_STATUS, request)

    async def observation_pause(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.OBSERVATION_PAUSE, request)

    async def observation_resume(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.OBSERVATION_RESUME, request)

    async def observation_revoke(self, request: object) -> JsonObject:
        return await self._support(ControlMethod.OBSERVATION_REVOKE, request)

    async def project(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        """Dispatch one CLI-only project request through the composed project application."""

        if self.project_application is None:
            raise ControlError("method_forbidden")
        if isinstance(request, Mapping):
            source = cast(Mapping[str, object], request)
        else:
            source = None
        if source is not None and source.get("operation") == "status":
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "Project status requires the STATUS operation with view=project and the held session and writer.",
                False,
            )
        return await self._support(ControlMethod.PROJECT, cast(object, request))

    async def _support(
        self,
        method: ControlMethod,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        handler = self.support_handlers.get(method)
        if handler is None:
            raise ControlError("method_forbidden")
        kwargs: dict[str, object] = {}
        if method in {
            ControlMethod.PRIVACY_GET_SETUP,
            ControlMethod.PRIVACY_GET_EFFECTIVE,
            ControlMethod.PRIVACY_PROPOSE_POLICY,
        }:
            kwargs["repository_privacy_context"] = repository_privacy_context
        result = await handler(request, **kwargs)
        if type(result) is not JsonObject or "privacy_projection" in result:
            raise TypeError("support_internal_body_invalid")
        return result

    async def projection_binding_facts(
        self,
        method: ControlMethod,
        request: object,
        result: UnprojectedControlBody,
    ) -> ProjectionBindingFacts:
        """Resolve the exact post-workflow route facts without exposing runtime internals."""

        source = _internal_json(result)
        request_id_value = getattr(request, "request_id", None)
        if request_id_value is None and isinstance(request, Mapping):
            request_id_value = cast(Mapping[object, object], request).get("request_id")
        original_request_id = request_id_value if type(request_id_value) is str else None
        session_value = source.get("session_id")
        if session_value is None:
            return ProjectionBindingFacts(original_request_id, None)
        if type(session_value) is not str:
            raise TypeError("projection_session_invalid")
        route = await self.start_catalog.resolve_route(session_value)
        task_value = source.get("task_id")
        # A delegated start deliberately carries the parent session/writer so the host remains
        # on its original lane while the child is still waiting for its one-time attach handle.
        # Bind that response to the parent route for disclosure authorization; requiring the
        # parent session's route to already belong to the not-yet-attached child would make the
        # public delegate operation fail before the child can ever attach.
        route_task_value = (
            source.get("parent_task_id")
            if method is ControlMethod.START and source.get("outcome") == "delegated"
            else task_value
        )
        if (
            route is None
            or route.state is not TaskRouteState.ACTIVE
            or route.session_id != session_value
            or type(route_task_value) is not str
            or route.task_id != route_task_value
        ):
            raise ControlError("privacy_projection_unavailable", retryable=True)
        return ProjectionBindingFacts(original_request_id, route.route_identity_digest)

    def authorizes_waiver(self, request: RespondRequest) -> bool:
        return self.waiver_authorizer(request)

    def authorizes_import_publication(self, request: object) -> bool:
        return self.import_publication_authorizer(request)

    def activate_import_publication(self, allocation: ImportAllocation) -> object:
        activate = getattr(self.import_publication_authorizer, "activate", None)
        if not callable(activate):
            raise PublicOperationError(
                PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
                "This exact import plan requires user authorization.",
                False,
                safe_details={"reason_code": "import_publication_authority_required"},
            )
        return cast(Callable[[ImportAllocation], object], activate)(allocation)

    def deactivate_import_publication(self, token: object, *, completed: bool) -> None:
        deactivate = getattr(self.import_publication_authorizer, "deactivate", None)
        if not callable(deactivate):
            return
        cast(Callable[..., None], deactivate)(token, completed=completed)

    def bind_import_publication(
        self,
        token: object,
        *,
        request_id: str,
        event_ids: tuple[str, ...],
    ) -> None:
        bind = getattr(self.import_publication_authorizer, "bind", None)
        if not callable(bind):
            raise PublicOperationError(
                PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
                "This exact import publication is not authorized.",
                False,
                safe_details={"reason_code": "import_publication_authority_required"},
            )
        cast(Callable[..., None], bind)(
            token,
            request_id=request_id,
            event_ids=event_ids,
        )

    def reconcile_completed_import_publication(self, allocation: ImportAllocation) -> None:
        reconcile = getattr(self.import_publication_authorizer, "reconcile_completed", None)
        if callable(reconcile):
            cast(Callable[[ImportAllocation], None], reconcile)(allocation)

    def receipt_versions_for(self, runtime: TaskRuntime) -> ReceiptVersionSlice:
        return self.receipt_version_resolver(runtime)

    async def conversation_review_context(
        self, runtime: TaskRuntime
    ) -> ConversationReviewContext | None:
        """The owner's conversation setting for this task's repository (ADR-049)."""

        if self.conversation_review_reader is None:
            return None
        return await self.conversation_review_reader(runtime)

    async def evaluate_semantic_check(
        self,
        frozen: FrozenCase,
        deterministic_findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: LineageEvaluation | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
        task_fact_gaps: tuple[str, ...] = (),
    ) -> object:
        evaluator = self.semantic_evaluator
        # The closing-review choice (issue #976) and the check-time task-fact codes (#977) reach
        # only evaluators that declare them, so an older double keeps its exact call shape
        # instead of failing into the fallbacks below.
        extra: dict[str, object] = {}
        if final_review and _accepts_keyword(evaluator, "final_review"):
            extra["final_review"] = True
        if task_fact_gaps and _accepts_keyword(evaluator, "task_fact_gaps"):
            extra["task_fact_gaps"] = task_fact_gaps
        # Production evaluators accept the task runtime for durable job/attempt coordination.
        # Test doubles may still be binary callables.
        try:
            return await evaluator(
                frozen,
                deterministic_findings,
                cast(TaskRuntime | None, runtime),
                lineage_evaluation,
                require_complete_specification=require_complete_specification,
                **extra,
            )
        except TypeError:
            try:
                return await evaluator(
                    frozen, deterministic_findings, cast(TaskRuntime | None, runtime)
                )
            except TypeError:
                return await evaluator(frozen, deterministic_findings)

    async def project_result_for_client(
        self,
        context: ClientProjectionContext,
        binding: ControlProjectionBinding,
        result: UnprojectedControlBody,
        *,
        _source_method: ControlMethod | None = None,
        _paginate: bool = True,
        _check_detail: str | None = None,
    ) -> ProjectedControlBody:
        if type(result) is DeliverySource:
            return StatusResultModel.model_validate(
                await self._continue_delivery(context, binding, result)
            )
        source = _projection_json(result)
        method = _source_method or binding.method
        if method is ControlMethod.CHECK and source.get("state") == "complete":
            # #1244 (D13): an agent's brief check names each finding briefly. A continuation
            # carries the first page's choice; a direct reply reads its own request.
            detail = _check_detail if _source_method is not None else _request_body_detail(binding)
            if detail == "brief":
                source = brief_check_body(source)
        if "privacy_projection" in source or (
            method in _WORKFLOW_METHODS and source.get("ok") is not True
        ):
            raise TypeError("unprojected_control_body_invalid")
        scope = self.disclosure_scope_for(binding, source)
        needs_route = scope.kind in {
            AuthorizationScopeKind.TASK,
            AuthorizationScopeKind.REQUEST,
        }
        if (binding.route_identity_digest is not None) != needs_route:
            raise TypeError("projection_route_binding_invalid")
        sink = resolve_client_disclosure_sink(context)
        project_status = source.get("view") == "project" and method in {
            ControlMethod.STATUS,
            ControlMethod.PROJECT,
        }
        advice_status = source.get("view") == "advice" and method is ControlMethod.STATUS
        # The advice page is also a valid empty structural snapshot when the observation/project
        # subsystem is not installed in a composed application.  There is no source-owned
        # selector to hydrate or revalidate in that shape.  Any populated advice item still
        # requires the project application below, preserving the fail-closed privacy boundary.
        advice_items: Sequence[JsonValue] | None = None
        if advice_status:
            page = source.get("page")
            raw_items = page.get("items") if isinstance(page, Mapping) else None
            if type(raw_items) in {tuple, list}:
                advice_items = cast(Sequence[JsonValue], raw_items)
        advice_needs_project_application = advice_status and (
            advice_items is None or bool(advice_items)
        )
        if project_status:
            from finishup.application.project_projection import (
                hydrate_project_status_coordination_resources,
                hydrate_project_status_text,
            )

            if self.project_application is None:
                raise ControlError("privacy_projection_unavailable", retryable=True)
            source = await hydrate_project_status_text(self.project_application, source, sink)
            source = await hydrate_project_status_coordination_resources(
                self.project_application, source, sink
            )
        elif advice_needs_project_application:
            from finishup.application.project_projection import (
                hydrate_status_advice_coordination_resources,
            )

            if self.project_application is None:
                raise ControlError("privacy_projection_unavailable", retryable=True)
            source = await hydrate_status_advice_coordination_resources(
                self.project_application, source, sink
            )
        items: list[CandidateContextItem] = []
        if project_status:
            from finishup.application.project_projection import source_denied_project_items

            items.extend(source_denied_project_items(source, scope))
            page = source.get("page")
            detections = page.get("detections") if isinstance(page, Mapping) else None
            if type(detections) in {tuple, list}:
                for index, raw_detection in enumerate(cast(Sequence[JsonValue], detections)):
                    if not isinstance(raw_detection, Mapping):
                        raise TypeError("project_detection_projection_invalid")
                    resource_paths = raw_detection.get("resource_paths")
                    if resource_paths is None:
                        continue
                    items.append(
                        CandidateContextItem(
                            f"coordination-resource-{index}",
                            DataCategory.REPOSITORY_EXCERPT,
                            scope,
                            f"/page/detections/{index}/resource_paths",
                            canonical_encode(resource_paths),
                        )
                    )
        if advice_status:
            page = source.get("page")
            raw_advice_items = page.get("items") if isinstance(page, Mapping) else None
            if type(raw_advice_items) in {tuple, list}:
                for index, raw_item in enumerate(cast(Sequence[JsonValue], raw_advice_items)):
                    if not isinstance(raw_item, Mapping):
                        raise TypeError("advice_item_projection_invalid")
                    resource_paths = raw_item.get("coordination_resource_paths")
                    if resource_paths is None:
                        continue
                    items.append(
                        CandidateContextItem(
                            f"coordination-advice-resource-{index}",
                            DataCategory.REPOSITORY_EXCERPT,
                            scope,
                            f"/page/items/{index}/coordination_resource_paths",
                            canonical_encode(resource_paths),
                        )
                    )
        coordination_resource_prefixes = tuple(
            item.origin_ref + "/"
            for item in items
            if item.item_id.startswith(("coordination-resource-", "coordination-advice-resource-"))
        )
        # Receipt prose is FinishUP-authored, but it can spell repository names (ADR-009, ADR-035).
        # For an agent each name span is its own repository-excerpt item, so the excerpt ceiling
        # and per-name provenance decide that span alone; the leaf's ordinary-category item
        # carries the prose with every name span already withheld. Owner views skip this.
        from finishup.application.receipt_projection import (
            HUMAN_TEXT_MAX_CHARS,
            ReceiptExcerpt,
            bounded_omitted_pointers,
            receipt_fragments,
            withheld_text,
        )

        def field_chars(pointer: str) -> int | None:
            # ``human_text`` has its own 32,768-character wire bound; a document field keeps
            # at least its original length (see ``withheld_text``).
            return HUMAN_TEXT_MAX_CHARS if pointer == "/human_text" else None

        receipt_excerpt_items: dict[str, ReceiptExcerpt] = {}
        leaf_excerpts: dict[str, list[ReceiptExcerpt]] = {}
        receipt_fragment_sources: dict[str, str] = {}
        receipt_provenance: ProjectionProvenanceContext | None = None
        if type(result) is ReceiptInternalResult and sink is LocalDisclosureSink.AGENT_CONTEXT:
            from finishup.application.receipt_projection import receipt_excerpts

            excerpts, authorship, attribution_frontier = await receipt_excerpts(
                self.runtime, result
            )
            if result.writer_id is not None:
                receipt_provenance = ProjectionProvenanceContext(
                    result.session_id,
                    result.writer_id,
                    attribution_frontier,
                    (),
                    authorship,
                )
            for index, excerpt in enumerate(excerpts):
                receipt_excerpt_items[excerpt.origin] = excerpt
                leaf_excerpts.setdefault(excerpt.pointer, []).append(excerpt)
                items.append(
                    CandidateContextItem(
                        f"receipt-excerpt-{index}",
                        DataCategory.REPOSITORY_EXCERPT,
                        scope,
                        excerpt.origin,
                        canonical_encode(excerpt.path),
                    )
                )
        for ordinal, (pointer, value) in enumerate(_leaves(source), start=1):
            if any(pointer.startswith(prefix) for prefix in coordination_resource_prefixes):
                continue
            # A leaf that cannot be classified stops the projection before any response exists, so
            # nothing is disclosed. The daemon reclassifies the escaping ProtocolValueError by
            # method: a write keeps the same-request_id remedy, a read is told to repeat. Naming it
            # privacy_projection_blocked here would be both wrong (no policy blocked it) and worse
            # for a write, since that reason is non-retryable and would describe a durable append
            # as a refusal.
            classification = (
                classify_result_leaf(method.value, source, pointer)
                if method in _WORKFLOW_METHODS
                else _classify_support_result_leaf(method, source, pointer)
            )
            if classification == "public_structural":
                continue
            spans = leaf_excerpts.get(pointer)
            content = canonical_encode(
                withheld_text(value, spans, max_chars=field_chars(pointer))
                if type(value) is str and spans
                else value
            )
            fragments = (
                receipt_fragments(content)
                if type(result) is ReceiptInternalResult and not spans
                else (content,)
            )
            for part, data in enumerate(fragments):
                origin = pointer if len(fragments) == 1 else f"{pointer}/@admission_part/{part}"
                if len(fragments) > 1:
                    receipt_fragment_sources[origin] = pointer
                items.append(
                    CandidateContextItem(
                        f"leaf-{ordinal}" if len(fragments) == 1 else f"leaf-{ordinal}-{part}",
                        classification,
                        scope,
                        origin,
                        data,
                    )
                )
        source_request_id = source.get("request_id")
        projection_request_id = (
            binding.original_request_id
            if _source_method is not None and binding.original_request_id is not None
            else source_request_id
            if type(source_request_id) is str
            else self.ids.new(IdKind.REQUEST)
        )
        provenance: ProjectionProvenanceContext | None = receipt_provenance
        if all(source.get(key) is not None for key in ("session_id", "writer_id")) and (
            source.get("subject_frontier") is not None or source.get("frontier") is not None
        ):
            # Row authorship is read by the service from the ledger at the page's own frozen
            # frontier; the resolver applies the provenance rule to it for this writer only.
            provenance = ProjectionProvenanceContext(
                cast(str, source["session_id"]),
                cast(str, source["writer_id"]),
                _frontier_for_projection(source),
                result.item_authorship if type(result) is StatusInternalResult else (),
                # tb4n5: who published each undeclared-reference name (exact leaf).
                result.leaf_authorship if type(result) is StatusInternalResult else (),
            )
        # One encoding serves both the subject digest and the audit context (issue #916);
        # ``canonical_digest`` is the SHA-256 of exactly these bytes.
        source_canonical = canonical_encode(source)
        candidate = CandidateContext(
            request_id=projection_request_id,
            channel=None,
            local_sink=sink,
            purpose="client_result_projection",
            scope=scope,
            subject_digest=f"sha256:{hashlib.sha256(source_canonical).hexdigest()}",
            provider_binding=None,
            items=tuple(items),
            provenance_context=(provenance if sink is LocalDisclosureSink.AGENT_CONTEXT else None),
            projection_audit_context=ProjectionAuditContext(
                binding.rpc_id,
                binding.method.value,
                binding.service_instance_id,
                binding.service_generation,
                binding.original_request_id,
                binding.route_identity_digest,
                binding.control_request_canonical,
                source_canonical,
            ),
        )
        decision = await self.privacy.prepare_local_disclosure(candidate)
        if type(decision) is LocalDisclosureUnavailable:
            raise ControlError("privacy_projection_unavailable", retryable=True)
        if type(decision) is LocalDisclosureApproved:
            completed = cast(LocalDisclosureApproved | LocalDisclosureBlocked, decision)
        elif type(decision) is LocalDisclosureBlocked:
            completed = cast(LocalDisclosureApproved | LocalDisclosureBlocked, decision)
        else:
            raise TypeError("local_disclosure_result_invalid")
        if project_status:
            from finishup.application.project_projection import revalidate_project_status_sources

            assert self.project_application is not None
            await revalidate_project_status_sources(self.project_application, source, sink)
        elif advice_needs_project_application:
            from finishup.application.project_projection import revalidate_status_advice_sources

            assert self.project_application is not None
            await revalidate_status_advice_sources(self.project_application, source, sink)
        withheld_spans: dict[str, list[ReceiptExcerpt]] = {}
        for omission in completed.omissions:
            excerpt = receipt_excerpt_items.get(omission.json_pointer)
            if excerpt is not None:
                withheld_spans.setdefault(excerpt.pointer, []).append(excerpt)
        marking_omissions = tuple(
            replace(
                omission,
                json_pointer=receipt_fragment_sources.get(
                    omission.json_pointer, omission.json_pointer
                ),
            )
            for omission in completed.omissions
            if omission.json_pointer not in receipt_excerpt_items
        )
        # JSON receipt content denied in its ordinary category still fails closed. A withheld
        # name span is replaced by a fixed token inside its string, preserving the receipt
        # document schema, the surrounding prose and structural coverage. The digest always
        # identifies the stored owner document, not the privacy-projected presentation.
        if (
            method is ControlMethod.RECEIPT
            and source.get("format") == "json"
            and any(
                omission.json_pointer == "/document"
                or omission.json_pointer.startswith("/document/")
                for omission in marking_omissions
            )
        ):
            raise ControlError("privacy_projection_blocked", retryable=False)
        projected: JsonValue = source
        marked = {omission.json_pointer for omission in marking_omissions}
        if withheld_spans:
            source_leaves = dict(_leaves(source))
            for pointer in sorted(withheld_spans.keys() - marked, key=str.encode):
                value = source_leaves[pointer]
                if type(value) is not str:
                    raise TypeError("receipt_projection_span_invalid")
                projected = _replace_pointer(
                    projected,
                    pointer,
                    withheld_text(value, withheld_spans[pointer], max_chars=field_chars(pointer)),
                )
        for omission in marking_omissions:
            # An omission whose pointer does not resolve means the privacy decision and the body
            # disagree. `_replace_pointer` raises a bounded, named ValueError rather than a bare
            # KeyError or IndexError; either way the projection stops before a response exists, so
            # the blocked content is never disclosed, and the daemon reclassifies by method.
            projected = _replace_pointer(
                projected,
                omission.json_pointer,
                {
                    "omitted": True,
                    "category": omission.category.value,
                    "reason": omission.reason,
                },
            )
        if not isinstance(projected, Mapping):
            raise TypeError("projected_control_body_invalid")
        receipt = completed.receipt
        projection = {
            "sink": completed.sink.value,
            "local_disclosure_receipt_id": receipt.receipt_id,
            "policy_id": receipt.policy.policy_id,
            "policy_version": str(receipt.policy.version),
            "policy_digest": receipt.policy.policy_digest,
            "included_categories": tuple(item.value for item in receipt.approved_categories),
            "blocked_categories": tuple(item.value for item in receipt.blocked_categories),
            # A withheld name span is reported at its real result leaf. Past the wire bound the
            # list coalesces to containing pointers; the audit keeps every individual decision.
            "omitted_pointers": bounded_omitted_pointers(
                tuple(
                    receipt_excerpt_items[item.json_pointer].pointer
                    if item.json_pointer in receipt_excerpt_items
                    else receipt_fragment_sources.get(item.json_pointer, item.json_pointer)
                    for item in completed.omissions
                )
            ),
            "projection_commitment": completed.case_or_projection_commitment,
        }
        complete = {**dict(projected.items()), "privacy_projection": projection}
        if method is ControlMethod.REVIEW:
            nested = complete.get("check_result")
            if not isinstance(nested, Mapping):
                raise TypeError("review_projection_shape_invalid")
            nested_complete = {**dict(nested.items()), "privacy_projection": projection}
            complete["check_result"] = nested_complete
            if canonical_encode(complete["privacy_projection"]) != canonical_encode(
                nested_complete["privacy_projection"]
            ):
                raise AssertionError("review_projection_identity_invalid")
        public = _public_model(method, complete)
        body = self._result_delivery_body(context, binding, method, source) if _paginate else None
        if body is None or mcp_delivery_bytes(complete) <= HOST_RESULT_BUDGET_BYTES:
            return public
        # The continuation request supplies the envelope and the held session and writer.
        excluded = {
            "actor",
            "client",
            "protocol_version",
            "schema_version",
            "session_id",
            "writer_id",
        }
        selector = (
            {
                "request_id": source["request_id"],
                **({"detail": "brief"} if source.get("detail") == "brief" else {}),
            }
            if method is ControlMethod.CHECK
            else {k: v for k, v in body.items() if k not in excluded}
        )
        if method is ControlMethod.STATUS:
            # A brief body omits requested_frontier when it equals result_frontier.
            requested = source.get("requested_frontier", source["result_frontier"])
            selector["at_frontier"] = cast(dict[str, JsonValue], requested)["sequence"]
        selector_code = (
            status_selector_code(selector)
            if method is ControlMethod.STATUS
            else receipt_selector_code(selector)
            if method is ControlMethod.RECEIPT
            else check_selector_code(selector)
        )
        paged = page_result(
            complete,
            method=method.value,
            selector=selector,
            writer_id=cast(str, body["writer_id"]),
            sink=sink.value,
            selector_code=selector_code,
        )
        self._keep_page_set(
            complete, method.value, selector, cast(str, body["writer_id"]), sink.value
        )
        model = {
            ControlMethod.CHECK: CheckResultModel,
            ControlMethod.RECEIPT: ReceiptResultModel,
            ControlMethod.STATUS: StatusResultModel,
        }[method]
        return model.model_validate(paged)

    def _keep_page_set(
        self,
        source: Mapping[str, JsonValue],
        method: str,
        selector: Mapping[str, JsonValue],
        writer_id: str,
        sink: str,
    ) -> DeliveryPageSet:
        """Keep one delivered page set in service memory, keyed as its handles name it (D12)."""

        from finishup.application.result_delivery import DeliveryHandle

        digest = content_digest(source)
        code = (
            status_selector_code(selector)
            if method == "status"
            else receipt_selector_code(selector)
            if method == "receipt"
            else check_selector_code(selector)
        )
        frontier = cast(Mapping[str, JsonValue], source["result_frontier"])
        handle = DeliveryHandle(
            cast(Literal["check", "receipt", "status"], method),
            cast(str, source["request_id"]),
            int(cast(str, frontier["sequence"])),
            1,
            digest.removeprefix("sha256:")[:8],
            code,
        )
        entry = DeliveryPageSet(
            cast(str, source["session_id"]),
            writer_id,
            sink,
            method,
            dict(selector),
            dict(source),
            digest,
            code,
            len(canonical_encode(dict(source))),
        )
        self.delivery_pages.put(handle.set_key, entry)
        return entry

    async def _continue_delivery(
        self,
        context: ClientProjectionContext,
        binding: ControlProjectionBinding,
        result: DeliverySource,
    ) -> dict[str, JsonValue]:
        """Serve the page a handle names (#1244, D12).

        The source is read and disclosed again. A redaction recorded after the set's frontier, or
        a changed sink or disclosure policy, refuses the continuation and names which. Otherwise:
        a kept set is served from its own copy, with ``ledger_moved_since`` when the fresh read no
        longer matches it; a miss rebuilds the set from the fresh read, at the handle's offset when
        its digest still matches, else from offset 0 with ``page_set_restarted``.
        """

        if result.redacted_since:
            raise invalid_cursor("delivery_redaction_recorded")
        sink = resolve_client_disclosure_sink(context).value
        handle = result.handle
        projected = await self.project_result_for_client(
            context,
            binding,
            result.result,
            _source_method=ControlMethod(result.method),
            _paginate=False,
            _check_detail=cast(str | None, result.selector.get("detail")),
        )
        fresh = dict(public_model_to_wire(projected))
        fresh_digest = content_digest(fresh)
        kept = self.delivery_pages.get(handle.set_key, result.session_id, result.writer_id)

        def page(
            source: Mapping[str, JsonValue],
            position: int,
            selector_code: str | None,
            *,
            moved: bool = False,
            restarted: bool = False,
        ) -> dict[str, JsonValue]:
            return page_result(
                source,
                method=result.method,
                selector=result.selector,
                writer_id=result.writer_id,
                sink=sink,
                position=position,
                request_id=result.request_id,
                selector_code=selector_code,
                ledger_moved_since=result.head_frontier if moved else None,
                page_set_restarted=restarted,
            )

        # The notice names a ledger that really moved; a call-local fact such as a check's
        # observation wait differs on any re-read and is simply kept as first delivered.
        moved = int(cast(str, result.head_frontier["sequence"])) > handle.frontier
        if kept is not None:
            if kept.sink != sink or disclosure_identity(kept.source) != disclosure_identity(fresh):
                raise invalid_cursor("delivery_disclosure_changed")
            if kept.digest.removeprefix("sha256:")[:8] != handle.digest_prefix:
                # A handle of a set a rebuild replaced: its offsets name other items.
                return page(kept.source, 0, kept.selector_code, moved=moved, restarted=True)
            if kept.digest == fresh_digest:
                # Unchanged: this read's own projection describes exactly these items.
                return page(fresh, handle.position, kept.selector_code)
            # The kept items were disclosed under the kept projection, so it travels with them.
            return page(kept.source, handle.position, kept.selector_code, moved=moved)
        fresh_frontier = cast(Mapping[str, JsonValue], fresh["result_frontier"])
        if int(cast(str, fresh_frontier["sequence"])) != handle.frontier:
            raise invalid_cursor()
        entry = self._keep_page_set(fresh, result.method, result.selector, result.writer_id, sink)
        if entry.digest.removeprefix("sha256:")[:8] == handle.digest_prefix:
            return page(fresh, handle.position, entry.selector_code)
        return page(fresh, 0, entry.selector_code, moved=moved, restarted=True)

    @staticmethod
    def _result_delivery_body(
        context: ClientProjectionContext,
        binding: ControlProjectionBinding,
        method: ControlMethod,
        source: Mapping[str, JsonValue],
    ) -> dict[str, JsonValue] | None:
        """The request body of a result that may become pages, else ``None`` (#1139).

        Only an agent's own MCP check, receipt, or ``delivery=paged`` status read is paged.
        Terminals (CLI), the native TUI and owner exports have no model context clip. The
        bridge's recovery probes and closure inventory read status without ``delivery=paged``
        and keep the complete result, as does the live, structural ``view=operation`` read.
        """
        if context.client_kind is not ControlClientKind.MCP_BRIDGE or context.owner_view:
            return None
        # Decide from the result first; parse the request body only for a pageable method.
        if not (
            method is ControlMethod.RECEIPT
            or (method is ControlMethod.CHECK and source.get("state") == "complete")
            or (method is ControlMethod.STATUS and source.get("view") != "operation")
        ):
            return None
        control = strict_json_parse(binding.control_request_canonical)
        body = control.get("body") if isinstance(control, dict) else None
        if not isinstance(body, dict):
            return None
        if method is ControlMethod.STATUS and body.get("delivery") != "paged":
            return None
        return body

    async def close(self) -> None:
        async with self._close_lock:
            if self._close_task is None:
                object.__setattr__(self, "_close_task", asyncio.create_task(self._close_once()))
            task = self._close_task
        assert task is not None
        await task

    async def _close_once(self) -> None:
        failure: BaseException | None = None
        try:
            # First: the sweep loop is already cancelled by this point, and a worker still parked
            # on a cross-process flock must not hold this teardown open.
            if self.observation_sweep_close is not None:
                self.observation_sweep_close()
        except BaseException as exc:
            failure = exc
        try:
            if self.verification_supervisor is not None:
                await self.verification_supervisor.stop()
        except BaseException as exc:
            if failure is None:
                failure = exc
        try:
            if self.advice_semantic_supervisor is not None:
                await self.advice_semantic_supervisor.stop()
        except BaseException as exc:
            if failure is None:
                failure = exc
        try:
            await self.privacy.close()
        except BaseException as exc:
            if failure is None:
                failure = exc
        try:
            await self.runtime.close()
        except BaseException as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            raise failure


type _ReadyContextProvider = Callable[[int, int], Awaitable["ServiceReadyContext"]]


@dataclass(frozen=True, slots=True, repr=False)
class ServiceReadyContext:
    """Validated, generation-bound dependencies for one fresh ready application."""

    service_generation: int
    vault_generation: int
    generation_is_current: Callable[[int, int], bool]
    start_catalog: StartCatalogPort
    publish_responses: PublishResponseCatalogPort
    runtime: BundleRuntimePort
    clock: ClockPort
    ids: IdPort
    verification_policy: VerificationPolicy
    privacy: PrivacyCoordinator
    status_cursor_key: bytes
    waiver_policy_digest: str
    semantic_evaluator: _SemanticEvaluator
    disclosure_scope_for: _ScopeResolver
    receipt_version_resolver: _ReceiptVersions
    waiver_authorizer: Callable[[RespondRequest], bool]
    import_publication_authorizer: Callable[[object], bool]
    profile: RuntimeProfile
    policy_packs: tuple[str, ...]
    version_manifest: Mapping[str, JsonValue]
    support_handlers: Mapping[ControlMethod, _SupportHandler] = field(
        default_factory=_empty_support_handlers
    )
    verification_supervisor: ObservationVerificationSupervisor | None = None
    rediscover_pending_verification: Callable[[], Awaitable[None]] | None = None
    advice_semantic_supervisor: ObservationAdviceSemanticSupervisor | None = None
    rediscover_pending_advice_semantic: Callable[[], Awaitable[None]] | None = None
    # Bounded, idempotent startup sweep that terminalizes egress audit rows an earlier
    # service generation left nonterminal after consuming a disclosure authorization.
    reconcile_started_egress_attempts: Callable[[], Awaitable[int]] | None = None
    connected_provider_ids: tuple[str, ...] = ()
    provider_credential_connected: bool = False
    # Structural presence of the declared fallback endpoint's credential (#582); never readiness.
    fallback_credential_connected: bool = False
    semantic_ready: bool = False
    observation_sweep: Callable[[], Awaitable[object]] | None = field(
        default=None, repr=False, compare=False
    )
    coordination_sweep: Callable[[], Awaitable[object]] | None = field(
        default=None, repr=False, compare=False
    )
    ready_recommendation_refresh: Callable[[], Awaitable[object]] | None = field(
        default=None, repr=False, compare=False
    )
    observation_sweep_close: Callable[[], None] | None = field(
        default=None, repr=False, compare=False
    )
    lineage: LineageCoordinator | None = field(default=None, repr=False, compare=False)
    project_application: ProjectApplication | None = field(default=None, repr=False, compare=False)
    host_lineage_registry: HostLineageRegistryPort | None = field(
        default=None, repr=False, compare=False
    )
    reconcile_observation_losses: Callable[[TaskRuntime], Awaitable[None]] | None = field(
        default=None, repr=False, compare=False
    )
    reconcile_observation_capture: Callable[[TaskRuntime], Awaitable[None]] | None = field(
        default=None, repr=False, compare=False
    )
    change_capture: ChangeCapturePort | None = field(default=None, repr=False, compare=False)
    input_snapshot_scope: (
        Callable[[RepositoryPrivacyContext, str], Awaitable[InputSnapshotScope | None]] | None
    ) = field(default=None, repr=False, compare=False)
    conversation_review_context: (
        Callable[[TaskRuntime], Awaitable[ConversationReviewContext | None]] | None
    ) = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.service_generation) is not int
            or type(self.vault_generation) is not int
            or self.service_generation <= 0
            or self.vault_generation <= 0
        ):
            raise ValueError("ready_generation_invalid")
        if type(self.connected_provider_ids) is not tuple or any(
            type(item) is not str for item in self.connected_provider_ids
        ):
            raise TypeError("connected_provider_ids_invalid")
        if type(self.provider_credential_connected) is not bool:
            raise TypeError("provider_credential_connected_invalid")
        if type(self.semantic_ready) is not bool:
            raise TypeError("semantic_ready_invalid")
        if self.observation_sweep is not None and not callable(self.observation_sweep):
            raise TypeError("observation_sweep_invalid")
        if self.coordination_sweep is not None and not callable(self.coordination_sweep):
            raise TypeError("coordination_sweep_invalid")
        if self.ready_recommendation_refresh is not None and not callable(
            self.ready_recommendation_refresh
        ):
            raise TypeError("ready_recommendation_refresh_invalid")
        if self.observation_sweep_close is not None and not callable(self.observation_sweep_close):
            raise TypeError("observation_sweep_close_invalid")
        if self.reconcile_observation_losses is not None and not callable(
            self.reconcile_observation_losses
        ):
            raise TypeError("reconcile_observation_losses_invalid")
        if self.reconcile_observation_capture is not None and not callable(
            self.reconcile_observation_capture
        ):
            raise TypeError("reconcile_observation_capture_invalid")
        # Readiness may never outrun the resolved binding. A connected provider that is not the
        # configured one leaves dispatch on the credential-unavailable path, so a readiness flag
        # set without it would report ready while every check reports unavailable.
        if self.semantic_ready and not self.provider_credential_connected:
            raise ValueError("semantic_ready_without_connected_provider_credential")

    def __repr__(self) -> str:
        return "ServiceReadyContext(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ReadyApplicationFactory:
    """Open one fresh application behind the daemon's exact generation fence."""

    context_provider: _ReadyContextProvider

    async def __call__(self, service_generation: int, vault_generation: int) -> Application:
        context = await self.context_provider(service_generation, vault_generation)
        if (
            type(context) is not ServiceReadyContext
            or context.service_generation != service_generation
            or context.vault_generation != vault_generation
        ):
            await _close_ready_context(context)
            raise ControlError("service_generation_changed", retryable=True)
        return await self.open(context)

    async def open(self, context: ServiceReadyContext) -> Application:
        if type(context) is not ServiceReadyContext:
            raise TypeError("service_ready_context_invalid")
        if not context.generation_is_current(context.service_generation, context.vault_generation):
            await _close_ready_context(context)
            raise ControlError("service_generation_changed", retryable=True)
        try:
            application = Application(
                context.start_catalog,
                context.publish_responses,
                context.runtime,
                context.clock,
                context.ids,
                context.verification_policy,
                context.privacy,
                context.status_cursor_key,
                context.waiver_policy_digest,
                context.semantic_evaluator,
                context.disclosure_scope_for,
                context.receipt_version_resolver,
                context.waiver_authorizer,
                context.import_publication_authorizer,
                context.profile,
                context.policy_packs,
                context.version_manifest,
                context.support_handlers,
                context.verification_supervisor,
                connected_provider_ids=context.connected_provider_ids,
                provider_credential_connected=context.provider_credential_connected,
                fallback_credential_connected=context.fallback_credential_connected,
                semantic_ready=context.semantic_ready,
                observation_sweep=context.observation_sweep,
                coordination_sweep=context.coordination_sweep,
                ready_recommendation_refresh=context.ready_recommendation_refresh,
                observation_sweep_close=context.observation_sweep_close,
                reconcile_observation_capture=context.reconcile_observation_capture,
                reconcile_observation_losses=context.reconcile_observation_losses,
                enforce_repository_identity=True,
                lineage=context.lineage,
                project_application=context.project_application,
                host_lineage_registry=context.host_lineage_registry,
                advice_semantic_supervisor=context.advice_semantic_supervisor,
                change_capture=context.change_capture,
                input_snapshot_scope=context.input_snapshot_scope,
                conversation_review_reader=context.conversation_review_context,
            )
            if context.reconcile_started_egress_attempts is not None:
                # Before any supervisor can admit a new physical attempt, so a live in-flight
                # dispatch can never be mistaken for an abandoned one.
                await context.reconcile_started_egress_attempts()
            if context.verification_supervisor is not None:
                await context.verification_supervisor.start()
            if context.rediscover_pending_verification is not None:
                await context.rediscover_pending_verification()
            if context.advice_semantic_supervisor is not None:
                await context.advice_semantic_supervisor.start()
            if context.rediscover_pending_advice_semantic is not None:
                await context.rediscover_pending_advice_semantic()
            return application
        except BaseException:
            await _close_ready_context(context)
            raise


async def _close_ready_context(context: object) -> None:
    if not isinstance(context, ServiceReadyContext):
        return
    failure: BaseException | None = None
    try:
        if context.observation_sweep_close is not None:
            context.observation_sweep_close()
    except BaseException as exc:
        failure = exc
    try:
        if context.verification_supervisor is not None:
            await context.verification_supervisor.stop()
    except BaseException as exc:
        if failure is None:
            failure = exc
    try:
        if context.advice_semantic_supervisor is not None:
            await context.advice_semantic_supervisor.stop()
    except BaseException as exc:
        if failure is None:
            failure = exc
    try:
        await context.privacy.close()
    except BaseException as exc:
        if failure is None:
            failure = exc
    try:
        await context.runtime.close()
    except BaseException as exc:
        if failure is None:
            failure = exc
    if failure is not None:
        raise failure
