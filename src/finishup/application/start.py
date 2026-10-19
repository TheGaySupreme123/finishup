"""Crash-safe create, attach, and resume orchestration for ``Application.start``."""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal, Protocol, cast

from finishup.application.lineage import (
    AttachHandle,
    DelegationOperation,
    DelegationPhase,
    DelegationRequest,
    LineageAcceptance,
    LineageCoordinator,
    LineageOrigin,
    LineageSnapshot,
)
from finishup.application.unit_of_work import (
    CatalogCompletion,
    CatalogLeaseYield,
    CatalogPhaseAdvance,
    CatalogQuarantine,
    PreparedMutation,
    run_catalog_transition,
    run_prepared_append,
)
from finishup.domain.coordination import WorkState
from finishup.domain.events import (
    LINEAGE_EVENT_SCHEMA_VERSION,
    LINEAGE_SESSION_EVENT_SCHEMA_VERSION,
    OBSERVATION_COORDINATOR_ACTOR_ID,
    SESSION_EVENT_SCHEMA_VERSION,
    TASK_STATEMENT_SESSION_OPENED_SCHEMA_VERSION,
    TASK_STATEMENT_SESSION_RESUMED_SCHEMA_VERSION,
    DelegationDeclaredPayload,
    EventDraft,
    EventSchema,
    RuntimeProfile,
    SessionOpenedPayload,
    SessionResumedPayload,
    encode_payload,
    media_type_for,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    Frontier,
    actor_id,
    event_id,
    format_rfc3339_millis,
    parse_rfc3339_millis,
    task_id,
    timestamp_from_datetime,
)
from finishup.ports.clock import ClockPort
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.host_lineage import HostLineageRegistryError, HostLineageRegistryReason
from finishup.ports.ids import IdPort
from finishup.ports.ledger import (
    AppendCommand,
    AppendEntry,
    AppendResult,
    OperationKind,
    OperationState,
    ProjectionView,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.ports.runtime import (
    BundleProvisionCommand,
    BundleProvisionMode,
    BundleRuntimePort,
    RouteAccess,
    RouteCommand,
    StartCompletionEvidence,
    StartMilestone,
    StartMilestoneExpectation,
    TaskRuntime,
)
from finishup.ports.start_catalog import (
    EncryptedResultRef,
    SafeReason,
    StartAllocation,
    StartCatalogPort,
    StartCommand,
    StartIdentityInput,
    StartMode,
    StartOperationLease,
    StartPhase,
    TaskRoute,
    TaskRouteState,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, validate_id
from finishup.protocol.models import (
    FrontierModel,
    IntegrationKind,
    StartCompactViewModel,
    StartRequest,
    StartVersionSliceModel,
    StatusCompactItemModel,
)

__all__ = [
    "StartInternalResult",
    "execute_start",
    "recover_delegation",
    "start_projection_wire",
]

_START_RESULT_MEDIA_TYPE = "application/vnd.yoetz.start_result+json"
_LEGACY_RECEIPT_BLOCKING_COUNT_UNKNOWN = "legacy_receipt_blocking_count_unknown"
_ENGINE_ACTOR_ID = "yoetz.engine"


class _StartApplication(Protocol):
    @property
    def start_catalog(self) -> StartCatalogPort: ...

    @property
    def runtime(self) -> BundleRuntimePort: ...

    @property
    def clock(self) -> ClockPort: ...

    @property
    def profile(self) -> RuntimeProfile: ...

    @property
    def policy_packs(self) -> tuple[str, ...]: ...

    @property
    def version_manifest(self) -> Mapping[str, JsonValue]: ...

    @property
    def ids(self) -> IdPort: ...

    @property
    def lineage(self) -> LineageCoordinator | None: ...


@dataclass(frozen=True, slots=True)
class StartInternalResult:
    """Closed structural START success before any client-specific privacy projection."""

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: str
    ok: Literal[True]
    outcome: Literal["attached", "created", "replayed", "delegated"]
    task_id: str
    session_id: str
    writer_id: str
    frontier: FrontierModel
    compact: StartCompactViewModel
    versions: StartVersionSliceModel
    attach_handle: AttachHandle | None = None
    parent_task_id: str | None = None
    depth: int | None = None
    origin: LineageOrigin | None = None
    acceptance: LineageAcceptance | None = None

    def __post_init__(self) -> None:
        if (
            self.protocol_version != "0.1"
            or self.schema_version != "1.0.0"
            or self.ok is not True
            or self.outcome not in {"attached", "created", "replayed", "delegated"}
            or type(self.frontier) is not FrontierModel
            or type(self.compact) is not StartCompactViewModel
            or type(self.versions) is not StartVersionSliceModel
        ):
            raise ValueError("invalid_start_internal_result")
        validate_id(IdKind.REQUEST, self.request_id)
        validate_id(IdKind.TASK, self.task_id)
        validate_id(IdKind.SESSION, self.session_id)
        validate_id(IdKind.WRITER, self.writer_id)
        lineage_values = (self.parent_task_id, self.depth, self.origin, self.acceptance)
        if any(value is not None for value in lineage_values) and not all(
            value is not None for value in lineage_values
        ):
            raise ValueError("invalid_start_lineage_fields")
        if self.attach_handle is not None:
            if self.outcome != "delegated" or self.attach_handle.task_id != self.task_id:
                raise ValueError("invalid_start_attach_handle")
        if self.outcome == "delegated":
            if self.attach_handle is None or self.parent_task_id is None or self.depth is None:
                raise ValueError("invalid_start_delegation_fields")
            if (
                self.origin is not LineageOrigin.PARENT_MINTED
                or self.acceptance is not LineageAcceptance.ACCEPTED
            ):
                raise ValueError("invalid_start_delegation_identity")
        elif self.attach_handle is not None:
            raise ValueError("invalid_start_attach_handle")

    def as_wire(self) -> dict[str, JsonValue]:
        value: dict[str, JsonValue] = {
            "compact": cast(JsonValue, self.compact.model_dump(mode="json", exclude_none=False)),
            "frontier": cast(JsonValue, self.frontier.model_dump(mode="json")),
            "ok": True,
            "outcome": self.outcome,
            "protocol_version": self.protocol_version,
            "request_id": self.request_id,
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "versions": cast(JsonValue, self.versions.model_dump(mode="json")),
            "writer_id": self.writer_id,
        }
        if self.parent_task_id is not None:
            value.update(
                {
                    "acceptance": self.acceptance.value if self.acceptance is not None else None,
                    # The internal result keeps depth numeric for lineage arithmetic; the
                    # canonical wire contract uses a positive integer encoded as a string.
                    "depth": str(self.depth) if self.depth is not None else None,
                    "origin": self.origin.value if self.origin is not None else None,
                    "parent_task_id": self.parent_task_id,
                }
            )
        if self.attach_handle is not None:
            value["attach_handle"] = {
                "handle": self.attach_handle.value,
                "child_task_id": self.attach_handle.task_id,
                "expires_at": format_rfc3339_millis(self.attach_handle.expires_at),
            }
        return value


def start_projection_wire(result: StartInternalResult) -> dict[str, JsonValue]:
    """Add the bound authoring scaffold only at the public projection boundary.

    The durable start-result object intentionally retains its established byte shape. Replays
    decode that legacy object and derive this deterministic scaffold from the same committed
    session, writer, and frontier bindings as a fresh result.
    """

    if type(result) is not StartInternalResult:
        raise TypeError("start_internal_result_invalid")

    def empty_draft_spine() -> dict[str, JsonValue]:
        return {
            "event_id": "",
            "occurred_at": "",
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
        }

    request: dict[str, JsonValue] = {
        "protocol_version": result.protocol_version,
        "schema_version": result.schema_version,
        "request_id": "",
        "actor": {"actor_id": "", "actor_type": ""},
        "client": {"kind": "", "version": "", "integration": ""},
        "session_id": result.session_id,
        "writer_id": result.writer_id,
        "expected_frontier": cast(JsonValue, result.frontier.model_dump(mode="json")),
        "event_drafts": [
            {
                **empty_draft_spine(),
                "schema": {"name": "plan_published", "version": "1.0.0"},
                "payload": {
                    "plan_version": 1,
                    "summary": "",
                    "obligation_refs": [""],
                },
            },
            {
                **empty_draft_spine(),
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "payload": {
                    "obligation_id": "",
                    "description": "",
                    "acceptance_criteria": "",
                    "evidence_expectation": "",
                    "status": "open",
                },
            },
        ],
    }
    return {
        **result.as_wire(),
        "next_request_template": {
            "evidential": False,
            "operation": "publish_work",
            "arguments": request,
        },
    }


class _StartContradiction(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool = False,
    safe_details: object | None = None,
) -> PublicOperationError:
    return PublicOperationError(code, message, retryable, safe_details=safe_details)


def _invalid_request() -> PublicOperationError:
    return _error(
        PublicErrorCode.INVALID_REQUEST,
        (
            "The start request is invalid. Use the tool input schema; client must include "
            "kind, version, and integration with exact allowed values."
        ),
    )


def _storage_corrupt(code: str) -> PublicOperationError:
    return _error(
        PublicErrorCode.STORAGE_CORRUPT,
        "The local start state is inconsistent.",
        safe_details={"reason_code": code},
    )


def _storage_unsafe() -> PublicOperationError:
    """Keep transient START-result I/O retryable without quarantining the catalog row."""

    return _error(
        PublicErrorCode.STORAGE_UNSAFE,
        "The start result is temporarily unavailable.",
        retryable=True,
    )


def _request_digest(request: StartRequest, command: StartCommand) -> str:
    commitments = command.identity_commitments
    attach_handle = request.attach_handle
    # The statement is part of request identity, so a retry with the same request_id and the
    # same statement replays and a different statement conflicts (issue #908). Present only when
    # supplied, so every earlier request keeps its exact digest.
    statement: dict[str, JsonValue] = (
        {}
        if request.task_statement is None
        else {"task_statement_digest": canonical_digest(request.task_statement)}
    )
    return canonical_digest(
        {
            **statement,
            "actor": cast(
                JsonValue,
                request.actor.model_dump(mode="json", exclude_none=False),
            ),
            "client": cast(JsonValue, request.client.model_dump(mode="json")),
            "identity_commitments": {
                "external_ref": commitments.external_ref_commitment,
                "task_title": commitments.title_commitment,
                "workspace_ref": commitments.workspace_ref_commitment,
            },
            "mode": request.mode,
            "protocol_version": request.protocol_version,
            "requested_view": request.requested_view,
            "repository_privacy_commitment": command.repository_privacy_commitment,
            "schema_version": request.schema_version,
            "session_id": request.session_id,
            "parent_session_id": request.parent_session_id,
            # Keep the bearer out of the durable request digest while making the selector part of
            # request identity.  A retry can therefore choose the task's rotated route session
            # without changing the operation identity, and a different handle cannot replay it.
            "attach_handle_digest": (
                None if attach_handle is None else canonical_digest(attach_handle.handle)
            ),
            "subagent_id": (request.subagent_id),
            "parent_tool_call_id": (
                None if request.parent_tool_call_id is None else request.parent_tool_call_id
            ),
            "correlation_id": (request.correlation_id),
        }
    )


async def _command(
    app: _StartApplication,
    request: StartRequest,
    repository_privacy_commitment: str | None,
    *,
    target_task_id: str | None = None,
    request_identity: StartRequest | None = None,
) -> StartCommand:
    try:
        identity = StartIdentityInput(
            request.task_title,
            request.workspace_ref,
            request.external_ref,
        )
        if (
            request.mode == "attach"
            and request.session_id is None
            and request.workspace_ref is None
        ):
            raise _invalid_request()
        commitments = await app.start_catalog.commit_identity(identity)
        parent_session_id = (
            request.session_id if request.mode == "delegate" else request.parent_session_id
        )
        provisional = StartCommand(
            operation_id=request.request_id,
            request_digest="sha256:" + "0" * 64,
            mode=StartMode(request.mode),
            identity_input=identity,
            identity_commitments=commitments,
            session_id=request.session_id,
            repository_privacy_commitment=repository_privacy_commitment,
            parent_session_id=parent_session_id,
            attach_handle=None if request.attach_handle is None else request.attach_handle.handle,
            target_task_id=target_task_id,
        )
        return StartCommand(
            operation_id=request.request_id,
            request_digest=_request_digest(request_identity or request, provisional),
            mode=provisional.mode,
            identity_input=identity,
            identity_commitments=commitments,
            session_id=request.session_id,
            repository_privacy_commitment=repository_privacy_commitment,
            parent_session_id=parent_session_id,
            attach_handle=None if request.attach_handle is None else request.attach_handle.handle,
            target_task_id=target_task_id,
        )
    except PublicOperationError:
        raise
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise _invalid_request() from exc


async def _reserve(catalog: StartCatalogPort, command: StartCommand) -> StartAllocation:
    return await run_catalog_transition(catalog, command)


def _version(app: _StartApplication, key: str) -> str:
    value = app.version_manifest.get(key)
    if type(value) is not str:
        raise _StartContradiction("start_bundle_invalid")
    return value


def _provision_command(
    app: _StartApplication,
    allocation: StartAllocation,
    *,
    route: TaskRoute | None = None,
    provision_mode: BundleProvisionMode | None = None,
) -> BundleProvisionCommand:
    lease = allocation.lease
    if lease is None:
        raise _StartContradiction("start_allocation_ambiguous")
    return BundleProvisionCommand(
        mode=(
            provision_mode
            if provision_mode is not None
            else (
                BundleProvisionMode.CREATED
                if allocation.route_action == "created"
                else BundleProvisionMode.ATTACHED
            )
        ),
        task_id=allocation.task_id,
        session_id=allocation.session_id,
        writer_id=allocation.writer_id,
        lifecycle_event_id=allocation.lifecycle_event_id,
        bundle_relpath=allocation.bundle_relpath,
        route_generation=allocation.route_generation,
        route_identity_digest=allocation.route_identity_digest,
        phase=allocation.phase.value,
        response_object_id=allocation.response_object_id,
        owner_generation=lease.owner_generation,
        lease_owner_id=lease.lease_owner_id,
        lease_generation=lease.lease_generation,
        lease_expires_at=lease.lease_expires_at,
        protocol_version=_version(app, "protocol_version"),
        engine_version=_version(app, "engine_version"),
        projection_version=_version(app, "projection_version"),
        bundle_schema_version=_version(app, "bundle_schema_version"),
        repository_privacy_commitment=(
            None if route is None else route.repository_privacy_commitment
        ),
        parent_task_id=None if route is None else route.parent_task_id,
        depth=0 if route is None else route.depth,
        lineage_digest=None if route is None else route.lineage_digest,
        origin=None if route is None else route.origin,
        acceptance=None if route is None else route.acceptance,
        work_state=WorkState.OPEN if route is None else route.work_state,
    )


async def _route_snapshot_for_provision(
    app: _StartApplication,
    allocation: StartAllocation,
) -> TaskRoute | None:
    """Read catalog metadata needed to provision the selected bundle.

    The start operation row intentionally freezes only the bundle identity and lease.  Lineage,
    work, and repository-privacy facts remain catalog-owned route metadata, so the provision
    command must carry a fresh authoritative snapshot instead of asking bundle inspection to
    reconstruct it.
    """

    lookup = getattr(app.start_catalog, "task_route", None)
    if not callable(lookup):
        # Small in-memory application doubles predate the task-route lookup.  The command's
        # identity fields remain sufficient for those tests; the ready composition always has
        # the real catalog method and therefore takes the metadata-preserving path.
        return None
    try:
        route = await cast(Callable[[str], Awaitable[TaskRoute | None]], lookup)(allocation.task_id)
    except (TypeError, ValueError) as exc:
        raise _StartContradiction("start_catalog_integrity") from exc
    if route is None or route.state is TaskRouteState.QUARANTINED:
        raise _StartContradiction("start_catalog_integrity")
    if (
        route.task_id != allocation.task_id
        or route.bundle_relpath != allocation.bundle_relpath
        or route.route_generation != allocation.route_generation
        or route.route_identity_digest != allocation.route_identity_digest
    ):
        raise _StartContradiction("start_route_contradiction")
    return route


def _expectation(
    allocation: StartAllocation,
    milestone: StartMilestone,
    result: EncryptedResultRef | None = None,
) -> StartMilestoneExpectation:
    return StartMilestoneExpectation(
        milestone=milestone,
        task_id=allocation.task_id,
        session_id=allocation.session_id,
        writer_id=allocation.writer_id,
        lifecycle_event_id=allocation.lifecycle_event_id,
        route_generation=allocation.route_generation,
        route_identity_digest=allocation.route_identity_digest,
        response_object_id=None if result is None else result.response_object_id,
        response_envelope_digest=None if result is None else result.envelope_digest,
        result_digest=None if result is None else result.result_digest,
    )


async def _advance(
    catalog: StartCatalogPort,
    allocation: StartAllocation,
    phase: StartPhase,
    result: EncryptedResultRef | None = None,
) -> StartAllocation:
    return await run_catalog_transition(catalog, CatalogPhaseAdvance(allocation, phase, result))


def _publication_channel(integration: IntegrationKind) -> PublicationChannel:
    return {
        IntegrationKind.COOPERATIVE_MCP: PublicationChannel.COOPERATIVE_MCP,
        IntegrationKind.LOCAL_CLI: PublicationChannel.LOCAL_CLI,
        IntegrationKind.CODEX_JSONL_IMPORT: PublicationChannel.CODEX_JSONL_IMPORT,
    }[integration]


async def _current_frontier(task: TaskRuntime) -> Frontier:
    return await task.ledger.load_frontier()


async def _lifecycle_append(
    app: _StartApplication,
    request: StartRequest,
    command: StartCommand,
    allocation: StartAllocation,
    task: TaskRuntime,
    *,
    force_open: bool = False,
    lineage_snapshot: LineageSnapshot | None = None,
) -> AppendResult:
    current = await _current_frontier(task)
    if allocation.route_action == "created" or force_open:
        payload = SessionOpenedPayload(
            task_title=request.task_title,
            client_kind=request.client.kind,
            client_version=request.client.version,
            integration=request.client.integration,
            profile=app.profile,
            external_ref=request.external_ref,
            workspace_ref=request.workspace_ref,
            parent_task_id=(
                None
                if lineage_snapshot is None or lineage_snapshot.parent_task_id is None
                else task_id(lineage_snapshot.parent_task_id)
            ),
            depth=None if lineage_snapshot is None else lineage_snapshot.depth,
            origin=None if lineage_snapshot is None else lineage_snapshot.origin,
            task_statement=request.task_statement,
        )
        schema = EventSchema(
            "session_opened",
            TASK_STATEMENT_SESSION_OPENED_SCHEMA_VERSION
            if request.task_statement is not None
            else LINEAGE_SESSION_EVENT_SCHEMA_VERSION
            if lineage_snapshot is not None
            else SESSION_EVENT_SCHEMA_VERSION,
        )
    else:
        # A statement supplied on reattach revises the task's current statement; the earlier
        # one stays in the ledger history (issue #908).
        payload = SessionResumedPayload(
            client_kind=request.client.kind,
            client_version=request.client.version,
            integration=request.client.integration,
            profile=app.profile,
            resumed_frontier=current,
            task_statement=request.task_statement,
        )
        schema = EventSchema(
            "session_resumed",
            SESSION_EVENT_SCHEMA_VERSION
            if request.task_statement is None
            else TASK_STATEMENT_SESSION_RESUMED_SCHEMA_VERSION,
        )
    payload_bytes = canonical_encode(encode_payload(payload))
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD,
        media_type_for(schema.name),
        allocation.task_id,
        app.clock.now_utc(),
    )
    payload_ref = await task.objects.finalize(
        await task.objects.stage(ObjectSource(data=payload_bytes), metadata)
    )
    draft = EventDraft(
        event_id=event_id(allocation.lifecycle_event_id),
        schema=schema,
        occurred_at=timestamp_from_datetime(app.clock.now_utc()),
        causal_parents=(),
        payload=payload,
        artifact_refs=(),
        evidence_refs=(),
    )
    channel = _publication_channel(request.client.integration)
    entry = AppendEntry(
        draft=draft,
        author=Actor(
            actor_id(_ENGINE_ACTOR_ID),
            ActorType.FINISHUP_ENGINE,
            AuthorshipAssurance.SERVICE_AUTHENTICATED,
        ),
        payload_object=payload_ref,
        payload_commitment=payload_ref.commitment,
        media_type=metadata.media_type,
        plaintext_size=payload_ref.plaintext_size,
        publication_channel=channel,
        coverage=coverage_for_channel(channel),
        projection_status="projected",
    )
    append = AppendCommand(
        task_id=allocation.task_id,
        session_id=allocation.session_id,
        writer_id=allocation.writer_id,
        operation_id=request.request_id,
        operation_kind=OperationKind.START,
        request_digest=command.request_digest,
        expected_frontier=current.sequence,
        entries=(entry,),
    )
    return await run_prepared_append(
        task.ledger,
        PreparedMutation(
            writer_id=allocation.writer_id,
            operation_id=request.request_id,
            request_digest=command.request_digest,
            expected_frontier=current.sequence,
            finalized_object_refs=(payload_ref,),
            command=append,
        ),
    )


def _compact_item(value: object, allocation: StartAllocation) -> StatusCompactItemModel:
    if type(value) is not tuple:
        raise _StartContradiction("start_lifecycle_contradiction")
    items = cast(tuple[object, ...], value)
    if len(items) != 1 or type(items[0]) is not StatusCompactItemModel:
        raise _StartContradiction("start_lifecycle_contradiction")
    item = items[0]
    if item.task_id != allocation.task_id or item.session_id != allocation.session_id:
        raise _StartContradiction("start_route_contradiction")
    return item


async def _build_result(
    app: _StartApplication,
    request: StartRequest,
    allocation: StartAllocation,
    task: TaskRuntime,
    frontier: Frontier,
    lineage_snapshot: LineageSnapshot | None = None,
) -> StartInternalResult:
    stored = await task.ledger.load_projection(allocation.session_id, ProjectionView.COMPACT)
    if stored is None or stored.frontier != frontier or stored.lag != 0 or stored.rebuild_required:
        raise _StartContradiction("start_lifecycle_contradiction")
    item = _compact_item(stored.state, allocation)
    compact = StartCompactViewModel.model_validate(
        {
            "coverage": item.coverage.model_dump(mode="json"),
            "current_plan_event_id": item.current_plan_event_id,
            "gaps": list(item.gaps),
            "ledger_freshness": item.freshness,
            "open_obligation_count": item.open_obligation_count,
            "unanswered_finding_count": item.unanswered_finding_count,
            "receipt_blocking_finding_count": item.receipt_blocking_finding_count,
        }
    )
    versions = StartVersionSliceModel.model_validate(
        {
            "engine_version": task.engine_version,
            "policy_packs": list(app.policy_packs),
            "projection_version": task.projection_version,
            "protocol_version": task.protocol_version,
        }
    )
    return StartInternalResult(
        protocol_version="0.1",
        schema_version="1.0.0",
        request_id=request.request_id,
        ok=True,
        outcome=allocation.route_action,
        task_id=allocation.task_id,
        session_id=allocation.session_id,
        writer_id=allocation.writer_id,
        frontier=FrontierModel.model_validate(dict(frontier.as_wire())),
        compact=compact,
        versions=versions,
        parent_task_id=None if lineage_snapshot is None else lineage_snapshot.parent_task_id,
        depth=None if lineage_snapshot is None else lineage_snapshot.depth,
        origin=None if lineage_snapshot is None else lineage_snapshot.origin,
        acceptance=None if lineage_snapshot is None else lineage_snapshot.acceptance,
    )


async def _publish_result(
    app: _StartApplication,
    allocation: StartAllocation,
    task: TaskRuntime,
    result: StartInternalResult,
) -> EncryptedResultRef:
    canonical = canonical_encode(cast(JsonValue, result.as_wire()))
    metadata = ObjectMetadata(
        ObjectKind.START_RESULT,
        _START_RESULT_MEDIA_TYPE,
        allocation.task_id,
        app.clock.now_utc(),
    )
    ref = await task.objects.finalize(
        await task.objects.stage(ObjectSource(data=canonical), metadata)
    )
    return EncryptedResultRef(
        response_object_id=ref.object_id,
        envelope_digest=ref.envelope_digest,
        result_canonical=canonical,
        result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
    )


def _decode_compact(value: object, outcome: object) -> StartCompactViewModel:
    if not isinstance(value, Mapping):
        raise ProtocolValueError("invalid_start_internal_result")
    compact = dict(cast(Mapping[str, object], value))
    legacy_count = compact.pop("unresolved_finding_count", None)
    if legacy_count is not None:
        if "unanswered_finding_count" in compact or "receipt_blocking_finding_count" in compact:
            raise ProtocolValueError("invalid_start_internal_result")
        compact["unanswered_finding_count"] = legacy_count
        if outcome == "created":
            # A create result is frozen at the first lifecycle event, before any finding can exist.
            compact["receipt_blocking_finding_count"] = "0"
        else:
            # An old attach result retained only the unanswered count. Responded actionable
            # findings cannot be reconstructed from that durable object, so preserve the replay
            # with an explicit unknown rather than manufacturing zero or declaring corruption.
            compact["receipt_blocking_finding_count"] = None
            gaps = compact.get("gaps")
            if not isinstance(gaps, list | tuple):
                raise ProtocolValueError("invalid_start_internal_result")
            compact["gaps"] = sorted(
                {*cast(list[str] | tuple[str, ...], gaps), _LEGACY_RECEIPT_BLOCKING_COUNT_UNKNOWN},
                key=str.encode,
            )
    return StartCompactViewModel.model_validate(compact)


def _decode_result(canonical: bytes) -> StartInternalResult:
    try:
        value = strict_json_parse(canonical)
        if canonical_encode(value) != canonical:
            raise ProtocolValueError("noncanonical_json")
        if (
            not isinstance(value, Mapping)
            or not {
                "compact",
                "frontier",
                "ok",
                "outcome",
                "protocol_version",
                "request_id",
                "schema_version",
                "session_id",
                "task_id",
                "versions",
                "writer_id",
            }.issubset(set(value))
            or set(value)
            - {
                "compact",
                "frontier",
                "ok",
                "outcome",
                "protocol_version",
                "request_id",
                "schema_version",
                "session_id",
                "task_id",
                "versions",
                "writer_id",
                "acceptance",
                "attach_handle",
                "depth",
                "origin",
                "parent_task_id",
            }
        ):
            raise ProtocolValueError("invalid_start_internal_result")
        source = cast(Mapping[str, object], value)
        protocol_version = source["protocol_version"]
        schema_version = source["schema_version"]
        outcome = source["outcome"]
        ok = source["ok"]
        if (
            protocol_version != "0.1"
            or schema_version != "1.0.0"
            or ok is not True
            or outcome not in {"attached", "created", "replayed", "delegated"}
        ):
            raise ProtocolValueError("invalid_start_internal_result")
        handle_value: AttachHandle | None = None
        if outcome == "delegated":
            raw_handle = source.get("attach_handle")
            if not isinstance(raw_handle, Mapping):
                raise ProtocolValueError("invalid_start_internal_result")
            handle = cast(Mapping[str, object], raw_handle)
            token = handle.get("handle")
            child = handle.get("child_task_id")
            expires = handle.get("expires_at")
            if type(token) is not str or type(child) is not str or type(expires) is not str:
                raise ProtocolValueError("invalid_start_internal_result")
            handle_value = AttachHandle(
                value=token,
                digest=canonical_digest(token),
                task_id=child,
                expires_at=parse_rfc3339_millis(expires),
            )
        return StartInternalResult(
            protocol_version="0.1",
            schema_version="1.0.0",
            request_id=cast(str, source["request_id"]),
            ok=True,
            outcome=cast(Literal["attached", "created", "replayed", "delegated"], outcome),
            task_id=cast(str, source["task_id"]),
            session_id=cast(str, source["session_id"]),
            writer_id=cast(str, source["writer_id"]),
            frontier=FrontierModel.model_validate(source["frontier"]),
            compact=_decode_compact(source["compact"], outcome),
            versions=StartVersionSliceModel.model_validate(source["versions"]),
            attach_handle=handle_value,
            parent_task_id=cast(str | None, source.get("parent_task_id")),
            depth=cast(int | None, source.get("depth")),
            origin=(
                None if source.get("origin") is None else LineageOrigin(cast(str, source["origin"]))
            ),
            acceptance=(
                None
                if source.get("acceptance") is None
                else LineageAcceptance(cast(str, source["acceptance"]))
            ),
        )
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise _StartContradiction("start_result_object_missing") from exc


async def _quarantine(
    catalog: StartCatalogPort,
    allocation: StartAllocation,
    contradiction: _StartContradiction,
) -> None:
    await run_catalog_transition(
        catalog,
        CatalogQuarantine(allocation, SafeReason(contradiction.code)),
    )


async def _reopen_result(
    allocation: StartAllocation,
    task: TaskRuntime,
) -> tuple[StartInternalResult, EncryptedResultRef]:
    response_object_id = allocation.response_object_id
    envelope_digest = allocation.response_envelope_digest
    canonical = allocation.response_result_canonical
    result_digest = allocation.response_result_digest
    if (
        response_object_id is None
        or envelope_digest is None
        or canonical is None
        or result_digest is None
    ):
        raise _StartContradiction("start_result_object_missing")
    try:
        ref = await task.objects.resolve_verified(response_object_id, envelope_digest)
    except OSError as exc:
        # An environmental read fault leaves the result-published catalog row resumable. Do not
        # turn it into a contradiction/quarantine: the same request can retry after the storage
        # transient clears.
        raise _storage_unsafe() from exc
    except (ProtocolValueError, PublicOperationError, TypeError, ValueError) as exc:
        raise _StartContradiction("start_result_object_missing") from exc
    if (
        ref.object_id != response_object_id
        or ref.envelope_digest != envelope_digest
        or ref.metadata.kind is not ObjectKind.START_RESULT
        or ref.metadata.task_id != allocation.task_id
        or ref.metadata.media_type != _START_RESULT_MEDIA_TYPE
        or ref.plaintext_size != len(canonical)
    ):
        raise _StartContradiction("start_result_object_missing")
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in task.objects.open_verified(ref):
            if type(chunk) is not bytes:
                raise _StartContradiction("start_result_object_missing")
            size += len(chunk)
            if size > len(canonical):
                raise _StartContradiction("start_result_object_missing")
            chunks.append(chunk)
    except _StartContradiction:
        raise
    except OSError as exc:
        raise _storage_unsafe() from exc
    except (ProtocolValueError, PublicOperationError, TypeError, ValueError) as exc:
        raise _StartContradiction("start_result_object_missing") from exc
    observed = b"".join(chunks)
    observed_digest = f"sha256:{hashlib.sha256(observed).hexdigest()}"
    if observed != canonical or observed_digest != result_digest:
        raise _StartContradiction("start_result_object_missing")
    result_ref = EncryptedResultRef(
        response_object_id=response_object_id,
        envelope_digest=envelope_digest,
        result_canonical=canonical,
        result_digest=result_digest,
    )
    return _decode_result(canonical), result_ref


async def _execute_standard_start(
    app: _StartApplication,
    request: StartRequest,
    *,
    repository_privacy_commitment: str | None = None,
    command: StartCommand | None = None,
    force_open: bool = False,
    lineage_snapshot: LineageSnapshot | None = None,
    provision_mode: BundleProvisionMode | None = None,
    sync_lineage: bool = True,
) -> StartInternalResult:
    """Execute one seven-step start operation against service-owned ports."""

    command = command or await _command(app, request, repository_privacy_commitment)
    allocation = await _reserve(app.start_catalog, command)
    if allocation.outcome == "replayed":
        if allocation.replayed_result is None:
            raise _storage_corrupt("start_catalog_integrity")
        try:
            result = _decode_result(allocation.replayed_result)
        except _StartContradiction as exc:
            raise _storage_corrupt(exc.code) from exc
        # A process can die after the durable start operation completed but before the lineage
        # projection was mirrored.  Replaying the catalog operation must therefore repair the
        # projection before returning; attach callbacks opt out because their coordinator performs
        # the route/handle compare-and-set as one operation.
        if sync_lineage:
            await _sync_start_lineage(
                app,
                result.task_id,
                result.session_id,
                repository_privacy_commitment,
            )
        return result

    task: TaskRuntime | None = None
    try:
        route = await _route_snapshot_for_provision(app, allocation)
        task = await app.runtime.provision_start(
            _provision_command(app, allocation, route=route, provision_mode=provision_mode)
        )
        await app.runtime.verify_start(
            task,
            _expectation(allocation, StartMilestone.BUNDLE_READY),
        )
        if allocation.phase is StartPhase.ROUTE_RESERVED:
            allocation = await _advance(
                app.start_catalog,
                allocation,
                StartPhase.BUNDLE_READY,
            )

        appended = await _lifecycle_append(
            app,
            request,
            command,
            allocation,
            task,
            force_open=force_open,
            lineage_snapshot=lineage_snapshot,
        )
        if (
            len(appended.accepted) != 1
            or appended.accepted[0].event_id != allocation.lifecycle_event_id
        ):
            raise _StartContradiction("start_lifecycle_contradiction")
        await app.runtime.verify_start(
            task,
            _expectation(allocation, StartMilestone.LIFECYCLE_COMMITTED),
        )
        if allocation.phase is StartPhase.BUNDLE_READY:
            allocation = await _advance(
                app.start_catalog,
                allocation,
                StartPhase.LIFECYCLE_COMMITTED,
            )

        if allocation.phase is StartPhase.RESULT_PUBLISHED:
            result, result_ref = await _reopen_result(allocation, task)
        else:
            result = await _build_result(
                app,
                request,
                allocation,
                task,
                appended.result_frontier,
                lineage_snapshot,
            )
            result_ref = await _publish_result(app, allocation, task, result)
            allocation = await _advance(
                app.start_catalog,
                allocation,
                StartPhase.RESULT_PUBLISHED,
                result_ref,
            )

        evidence: StartCompletionEvidence = await app.runtime.verify_start(
            task,
            _expectation(
                allocation,
                StartMilestone.RESULT_PUBLISHED,
                result_ref,
            ),
        )
        await run_catalog_transition(
            app.start_catalog,
            CatalogCompletion(allocation, result_ref, evidence),
        )
        if sync_lineage:
            await _sync_start_lineage(
                app,
                allocation.task_id,
                allocation.session_id,
                repository_privacy_commitment,
            )
        return result
    except _StartContradiction as exc:
        await _quarantine(app.start_catalog, allocation, exc)
        raise _storage_corrupt(exc.code) from exc
    except PublicOperationError as exc:
        if exc.code is not PublicErrorCode.BUNDLE_BUSY or not exc.retryable:
            raise
        # A returned busy error is a definite stopped attempt, unlike cancellation or a
        # lost response. Preserve every durable milestone and only relinquish this lease.
        # A stale owner, expired lease, or a busy catalog cannot promise immediate replay.
        try:
            await run_catalog_transition(app.start_catalog, CatalogLeaseYield(allocation))
        except PublicOperationError:
            raise exc
        producer = exc.safe_details.get("reason_code")
        reason = {
            "runtime_rebind_busy": "start_runtime_rebind_retry_ready",
            "catalog_busy": "start_catalog_retry_ready",
        }.get(producer if isinstance(producer, str) else "", "start_busy_retry_ready")
        raise _error(
            PublicErrorCode.BUNDLE_BUSY,
            "The start attempt yielded its lease; replay the identical request after contention clears.",
            retryable=True,
            safe_details={"reason_code": reason},
        ) from exc
    finally:
        if task is not None:
            await app.runtime.release(task)


def _lineage_unavailable() -> PublicOperationError:
    return _error(
        PublicErrorCode.SERVICE_UNAVAILABLE,
        "The lineage service is temporarily unavailable.",
        retryable=True,
        safe_details={"reason_code": "lineage_service_unavailable"},
    )


def _lineage_for(app: _StartApplication) -> LineageCoordinator:
    lineage = getattr(app, "lineage", None)
    if not isinstance(lineage, LineageCoordinator):
        raise _lineage_unavailable()
    return lineage


async def _sync_start_lineage(
    app: _StartApplication,
    task_id: str,
    session_id: str,
    repository_privacy_commitment: str | None,
) -> None:
    """Mirror a completed start route into the single service lineage authority."""

    lineage = getattr(app, "lineage", None)
    if lineage is None:
        return
    if not isinstance(lineage, LineageCoordinator):
        raise _lineage_unavailable()
    route_lookup = getattr(app.start_catalog, "task_route", None)
    route = (
        await cast(Callable[[str], Awaitable[TaskRoute | None]], route_lookup)(task_id)
        if callable(route_lookup)
        else None
    )
    existing = await lineage.store.get_task(task_id)
    # A terminal replay can name a session that has since been superseded by a later successful
    # start.  Rebinding lineage to that stale result would either violate the catalog's per-session
    # transition rules or make the lineage projection disagree with the current route.  When the
    # route is active, its session is the authoritative binding for this reconciliation; a pending
    # initializing route keeps the operation's own session until its completion phase is durable.
    effective_session_id = (
        route.session_id
        if route is not None and route.state is TaskRouteState.ACTIVE
        else session_id
    )
    if existing is None:
        if route is not None and route.parent_task_id is not None:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The task lineage is inconsistent.",
                safe_details={"reason_code": "lineage_child_missing"},
            )
        await lineage.register_root(
            task_id=task_id,
            session_id=effective_session_id,
            repository_commitment=(
                repository_privacy_commitment
                if repository_privacy_commitment is not None
                else None
                if route is None
                else route.repository_privacy_commitment
            ),
        )
        return
    await lineage.bind_session(task_id=task_id, session_id=effective_session_id)


async def _merge_host_annotation(
    app: _StartApplication,
    request: StartRequest,
    child: LineageSnapshot,
    *,
    parent_session_id: str | None = None,
    validate_only: bool = False,
) -> None:
    """Hand host correlation fields to the service-owned annotation seam after binding.

    Host adapters may install a merger on the coordinator.  The task relationship and immutable
    origin are checked by that coordinator; this helper only selects the parent's current session
    when an attach request does not carry the original parent selector.
    """

    if (
        request.subagent_id is None
        and request.parent_tool_call_id is None
        and request.correlation_id is None
    ):
        return
    lineage = _lineage_for(app)
    parent_task_id = child.parent_task_id
    if parent_task_id is None:
        return
    selected_parent_session = parent_session_id
    if selected_parent_session is None:
        parent = await lineage.store.get_task(parent_task_id)
        if parent is None:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The parent task is missing.",
                safe_details={"reason_code": "lineage_parent_not_found"},
            )
        selected_parent_session = parent.active_session_id
    if selected_parent_session is None:
        raise _error(
            PublicErrorCode.SESSION_CONFLICT,
            "The parent task has no attachable session.",
            safe_details={"reason_code": "lineage_parent_session_invalid"},
        )
    merger = getattr(lineage, "merge_host_annotation", None)
    if not callable(merger):
        return
    try:
        await cast(Callable[..., Awaitable[None]], merger)(
            parent_task_id=parent_task_id,
            child_task_id=child.task_id,
            parent_session_id=selected_parent_session,
            host=None,
            subagent_id=request.subagent_id,
            parent_tool_call_id=request.parent_tool_call_id,
            correlation_id=request.correlation_id,
            phase="start",
            validate_only=validate_only,
        )
    except HostLineageRegistryError as exc:
        code = PublicErrorCode.SESSION_CONFLICT
        reason = "host_lineage_annotation_invalid"
        if exc.reason is HostLineageRegistryReason.STORAGE_BUSY:
            code = PublicErrorCode.BUNDLE_BUSY
            reason = "catalog_busy"
        elif exc.reason in {
            HostLineageRegistryReason.STORAGE_CORRUPT,
            HostLineageRegistryReason.MIGRATION_REQUIRED,
        }:
            code = PublicErrorCode.STORAGE_CORRUPT
        raise _error(
            code,
            "The host lineage annotation could not be bound.",
            retryable=exc.retryable,
            safe_details={"reason_code": reason},
        ) from exc


async def _validate_handle_identity(
    app: _StartApplication,
    request: StartRequest,
    handle: AttachHandle,
) -> None:
    """Check every optional selector against the child before consuming its handle."""

    if request.session_id is not None:
        selected = await app.start_catalog.resolve_route(request.session_id)
        if selected is None or selected.task_id != handle.task_id:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The attach selectors conflict.",
                safe_details={"reason_code": "selector_conflict"},
            )

    if request.workspace_ref is None and request.external_ref is None:
        return
    source_lookup = getattr(app.start_catalog, "task_source_provenance", None)
    if not callable(source_lookup):
        raise _lineage_unavailable()
    source = await cast(Callable[[str], Awaitable[object | None]], source_lookup)(handle.task_id)
    if source is None:
        raise _error(
            PublicErrorCode.SESSION_NOT_FOUND,
            "The attach handle was not found.",
            safe_details={"reason_code": "attach_handle_invalid"},
        )
    identity = await app.start_catalog.commit_identity(
        StartIdentityInput(request.task_title, request.workspace_ref, request.external_ref)
    )
    if (
        getattr(source, "workspace_ref_commitment", None) != identity.workspace_ref_commitment
        or getattr(source, "external_ref_commitment", None) != identity.external_ref_commitment
    ):
        raise _error(
            PublicErrorCode.SESSION_CONFLICT,
            "The attach identity conflicts.",
            safe_details={"reason_code": "selector_conflict"},
        )


async def _execute_handle_attach(
    app: _StartApplication,
    request: StartRequest,
    repository_privacy_commitment: str | None,
) -> StartInternalResult:
    lineage = _lineage_for(app)
    attach_model = request.attach_handle
    if attach_model is None:
        raise _invalid_request()
    token = attach_model.handle

    async def _replay_check(current_handle: AttachHandle) -> bool:
        """Allow only a completed child-start operation to recover its capability.

        The handle row intentionally stores no public request identity.  The start catalog does
        store that identity, so consult its private operation lookup before a consumed capability
        can invoke the callback.  This keeps a second request from rotating the child route and
        then failing the single-use compare-and-set.  The durable start operation still performs
        the full request-digest check when the callback runs.
        """

        lookup = getattr(app.start_catalog, "_operation_by_key", None)
        if callable(lookup):
            try:
                record = cast(Callable[[str], object], lookup)(request.request_id)
            except (PublicOperationError, TypeError, ValueError):
                return False
            return (
                getattr(record, "task_id", None) == current_handle.task_id
                and getattr(record, "state", None) == "complete"
            )
        state = getattr(app.start_catalog, "_state", None)
        operations = getattr(state, "operations", None)
        if isinstance(operations, Mapping):
            record = cast(Mapping[str, object], operations).get(request.request_id)
            return (
                getattr(record, "task_id", None) == current_handle.task_id
                and getattr(record, "state", None) == "complete"
            )
        return False

    handle = await lineage.validate_attach(
        handle_value=token,
        repository_commitment=repository_privacy_commitment,
        replay_check=_replay_check,
    )
    # The model repeats service-returned structural facts so a caller cannot swap a valid bearer
    # token into a request naming another child or expiry.  The token itself remains opaque and
    # is never included in a public error.
    if (
        attach_model.child_task_id != handle.task_id
        or attach_model.expires_at != format_rfc3339_millis(handle.expires_at)
    ):
        raise _error(
            PublicErrorCode.SESSION_CONFLICT,
            "The attach identity conflicts.",
            safe_details={"reason_code": "selector_conflict"},
        )
    await _validate_handle_identity(app, request, handle)
    child = await lineage.store.get_task(handle.task_id)
    if child is None:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The child task is missing.",
            safe_details={"reason_code": "lineage_child_missing"},
        )
    # Reject contradictory or ambiguous host selectors before rotating the child session or
    # consuming its capability. The final merge remains replayable if a concurrent observation
    # or transient registry failure changes the answer after this read-only preflight.
    await _merge_host_annotation(app, request, child, validate_only=True)
    route_lookup = getattr(app.start_catalog, "task_route", None)
    if not callable(route_lookup):
        raise _lineage_unavailable()

    async def _start_child(current_handle: AttachHandle) -> StartInternalResult:
        # Resolve the route only while the lineage coordinator's single-use lock is held by
        # attach_with_operation.  This prevents two concurrent attachers from each rotating the
        # child route before one of their handles wins the compare-and-set.
        route = await cast(Callable[[str], Awaitable[TaskRoute | None]], route_lookup)(
            current_handle.task_id
        )
        if route is None or route.state is TaskRouteState.QUARANTINED:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The attach handle was not found.",
                safe_details={"reason_code": "attach_handle_invalid"},
            )
        selector_session = current_handle.consumed_session_id or route.session_id
        synthetic = request.model_copy(
            update={
                "session_id": selector_session,
                "parent_session_id": None,
            }
        )
        command = await _command(
            app,
            synthetic,
            repository_privacy_commitment,
            target_task_id=current_handle.task_id,
            request_identity=request,
        )
        snapshot = await lineage.store.get_task(current_handle.task_id)
        if snapshot is None:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The child task is missing.",
                safe_details={"reason_code": "lineage_child_missing"},
            )
        return await _execute_standard_start(
            app,
            synthetic,
            repository_privacy_commitment=repository_privacy_commitment,
            command=command,
            force_open=True,
            lineage_snapshot=snapshot,
            # The atomic attach callback updates the lineage projection after the start catalog
            # operation completes.  Calling the projection synchronizer here would re-enter the
            # coordinator lock and would also create a split window between route and handle.
            sync_lineage=False,
        )

    result, snapshot = await lineage.attach_with_operation(
        handle_value=token,
        repository_commitment=repository_privacy_commitment,
        request_id=request.request_id,
        replay_check=_replay_check,
        operation=_start_child,
    )
    await _merge_host_annotation(app, request, snapshot)
    return result


async def _execute_self_registration(
    app: _StartApplication,
    request: StartRequest,
    repository_privacy_commitment: str | None,
) -> StartInternalResult:
    lineage = _lineage_for(app)
    parent_session_id = request.parent_session_id
    if parent_session_id is None:
        raise _invalid_request()
    if request.session_id is not None:
        # Self-registration creates a new child. An existing task selector cannot be silently
        # replaced by that new child's session, even when it names the parent itself.
        raise _error(
            PublicErrorCode.SESSION_CONFLICT,
            "The child creation selectors conflict.",
            safe_details={"reason_code": "selector_conflict"},
        )
    command = await _command(app, request, repository_privacy_commitment)
    child = await lineage.self_register(
        operation_id=request.request_id,
        request_digest=command.request_digest,
        parent_session_id=parent_session_id,
        repository_commitment=repository_privacy_commitment,
        workspace_commitment=command.identity_commitments.workspace_ref_commitment,
        external_commitment=command.identity_commitments.external_ref_commitment,
    )
    child_session_id = child.active_session_id
    if child_session_id is None:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The self-registered task is missing its session.",
            safe_details={"reason_code": "lineage_child_missing"},
        )
    synthetic = request.model_copy(
        update={
            "mode": "attach",
            "session_id": child_session_id,
            "parent_session_id": None,
        }
    )
    child_command = await _command(
        app,
        synthetic,
        repository_privacy_commitment,
        target_task_id=child.task_id,
        request_identity=request,
    )
    result = await _execute_standard_start(
        app,
        synthetic,
        repository_privacy_commitment=repository_privacy_commitment,
        command=child_command,
        force_open=True,
        lineage_snapshot=child,
        provision_mode=BundleProvisionMode.CREATED,
    )
    await _merge_host_annotation(
        app,
        request,
        child,
        parent_session_id=parent_session_id,
    )
    return result


def _synthetic_child_allocation(
    app: _StartApplication,
    operation: DelegationOperation,
    route: TaskRoute,
    *,
    operation_id: str,
) -> StartAllocation:
    now = app.clock.now_utc()
    lease_owner = getattr(app.start_catalog, "_lease_owner_id", None)
    if type(lease_owner) is not str:
        lease_owner = app.ids.new(IdKind.SERVICE_INSTANCE)
    owner_generation = getattr(app.start_catalog, "generation", 1)
    if type(owner_generation) is not int or owner_generation < 1:
        owner_generation = 1
    writer = app.ids.new(IdKind.WRITER)
    lifecycle = "evt_" + operation_id.removeprefix("req_")
    lease = StartOperationLease(
        owner_generation=owner_generation,
        lease_owner_id=lease_owner,
        lease_generation=1,
        lease_expires_at=now + timedelta(seconds=300),
    )
    return StartAllocation(
        outcome="reserved",
        route_action="created",
        task_id=route.task_id,
        session_id=route.session_id,
        writer_id=writer,
        lifecycle_event_id=lifecycle,
        bundle_relpath=route.bundle_relpath,
        route_generation=route.route_generation,
        route_identity_digest=route.route_identity_digest,
        phase=StartPhase.ROUTE_RESERVED,
        response_object_id=None,
        response_envelope_digest=None,
        response_result_canonical=None,
        response_result_digest=None,
        lease=lease,
        replayed_result=None,
    )


async def _provision_delegated_child(
    app: _StartApplication,
    operation: DelegationOperation,
) -> None:
    route_lookup = getattr(app.start_catalog, "task_route", None)
    if not callable(route_lookup):
        raise _lineage_unavailable()
    route = await cast(Callable[[str], Awaitable[TaskRoute | None]], route_lookup)(
        operation.child_task_id
    )
    if route is None or route.state is TaskRouteState.QUARANTINED:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The delegated child route is unavailable.",
            safe_details={"reason_code": "lineage_child_missing"},
        )
    allocation = _synthetic_child_allocation(
        app, operation, route, operation_id=operation.operation_id
    )
    task: TaskRuntime | None = None
    try:
        task = await app.runtime.provision_start(_provision_command(app, allocation, route=route))
        await app.runtime.verify_start(task, _expectation(allocation, StartMilestone.BUNDLE_READY))
    finally:
        if task is not None:
            await app.runtime.release(task)


async def provision_lineage_recovery(
    app: _StartApplication, operation: DelegationOperation
) -> TaskRuntime:
    """Open a completed delegation's inert bundle for service-owned recovery evidence.

    This does not activate a route, open an agent session, or consume its handle. The caller owns
    the returned runtime lease and must release it.
    """

    route = await app.start_catalog.task_route(operation.child_task_id)
    if (
        route is None
        or route.state is not TaskRouteState.INITIALIZING
        or operation.phase is not DelegationPhase.TERMINAL
    ):
        raise _error(
            PublicErrorCode.SESSION_CONFLICT,
            "The delegated recovery route is inconsistent.",
            safe_details={"reason_code": "lineage_child_missing"},
        )
    allocation = _synthetic_child_allocation(
        app, operation, route, operation_id=operation.operation_id
    )
    return await app.runtime.provision_start(_provision_command(app, allocation, route=route))


async def _append_delegation_event(
    app: _StartApplication,
    operation: DelegationOperation,
) -> None:
    parent_task_id = operation.parent_task_id
    parent_session_id = operation.parent_session_id
    operation_id = operation.operation_id
    request_digest = operation.request_digest
    child_task_id = operation.child_task_id
    depth = operation.depth
    binding = await app.start_catalog.session_binding(parent_session_id)
    if binding is None or binding.task_id != parent_task_id:
        route_lookup = getattr(app.start_catalog, "task_route", None)
        route = (
            await cast(Callable[[str], Awaitable[TaskRoute | None]], route_lookup)(parent_task_id)
            if callable(route_lookup)
            else None
        )
        if route is None:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The parent task was not found.",
                safe_details={"reason_code": "lineage_parent_not_found"},
            )
        binding = await app.start_catalog.session_binding(route.session_id)
    if binding is None or binding.task_id != parent_task_id:
        raise _error(
            PublicErrorCode.SESSION_CONFLICT,
            "The parent session is no longer active.",
            safe_details={"reason_code": "lineage_parent_session_invalid"},
        )
    runtime = await app.runtime.route(
        RouteCommand(
            binding.session_id,
            binding.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    try:
        stable_event_id = event_id("evt_" + operation_id.removeprefix("req_"))

        def _historical_writer(session_id: str) -> str | None:
            lookup = getattr(app.start_catalog, "_writer_for_session", None)
            if not callable(lookup):
                return None
            try:
                candidate = lookup(session_id)
            except (TypeError, ValueError, PublicOperationError):
                return None
            return candidate if type(candidate) is str else None

        # A parent session may have rotated after the process crashed between the ledger append
        # and the lineage phase marker.  The bundle is task-scoped, so the current runtime can
        # inspect the operation row under the historical writer even though routing that retired
        # session is intentionally refused.  This preserves exactly-once append semantics without
        # rebinding the parent host session.
        candidate_writers = tuple(
            dict.fromkeys(
                writer
                for writer in (
                    binding.writer_id,
                    _historical_writer(parent_session_id),
                )
                if writer is not None
            )
        )
        for candidate_writer in candidate_writers:
            prior = await runtime.ledger.lookup_operation(candidate_writer, operation_id)
            if prior is None:
                continue
            if (
                prior.operation_kind is not OperationKind.PUBLISH_WORK
                or prior.request_digest != request_digest
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The delegation event operation is inconsistent.",
                    safe_details={"reason_code": "lineage_event_operation_conflict"},
                )
            if prior.state is not OperationState.COMPLETE or prior.result_canonical is None:
                raise _error(
                    PublicErrorCode.OPERATION_PENDING,
                    "The delegation event is still being committed.",
                    retryable=True,
                    safe_details={"reason_code": "lineage_event_operation_pending"},
                )
            try:
                stored = strict_json_parse(prior.result_canonical)
                if not isinstance(stored, Mapping):
                    raise ValueError("lineage_event_result_invalid")
                stored_map = cast(Mapping[str, JsonValue], stored)
                accepted = stored_map.get("accepted")
                if not isinstance(accepted, list | tuple) or len(accepted) != 1:
                    raise ValueError("lineage_event_result_invalid")
                first = accepted[0]
                if not isinstance(first, Mapping):
                    raise ValueError("lineage_event_result_invalid")
                first_map = cast(Mapping[str, JsonValue], first)
                if first_map.get("event_id") != stable_event_id:
                    raise ValueError("lineage_event_result_invalid")
            except (TypeError, ValueError) as exc:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The delegation event result is inconsistent.",
                    safe_details={"reason_code": "lineage_event_result_invalid"},
                ) from exc
            return
        current = await runtime.ledger.load_frontier()
        payload = DelegationDeclaredPayload(
            child_task_id=task_id(child_task_id),
            handle_digest=operation.handle_digest,
            depth=depth,
            project_id=operation.project_id,
            membership_generation=operation.membership_generation,
        )
        schema = EventSchema("delegation_declared", LINEAGE_EVENT_SCHEMA_VERSION)
        payload_bytes = canonical_encode(encode_payload(payload))
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD,
            media_type_for(schema.name),
            parent_task_id,
            app.clock.now_utc(),
        )
        payload_ref = await runtime.objects.finalize(
            await runtime.objects.stage(ObjectSource(data=payload_bytes), metadata)
        )
        draft = EventDraft(
            event_id=stable_event_id,
            schema=schema,
            occurred_at=timestamp_from_datetime(app.clock.now_utc()),
            causal_parents=(),
            payload=payload,
            artifact_refs=(),
            evidence_refs=(),
        )
        coverage = coverage_for_channel(PublicationChannel.ENGINE_DERIVED)
        entry = AppendEntry(
            draft=draft,
            author=Actor(
                actor_id(OBSERVATION_COORDINATOR_ACTOR_ID),
                ActorType.HARNESS,
                AuthorshipAssurance.HARNESS_OBSERVED,
            ),
            payload_object=payload_ref,
            payload_commitment=payload_ref.commitment,
            media_type=metadata.media_type,
            plaintext_size=payload_ref.plaintext_size,
            publication_channel=PublicationChannel.ENGINE_DERIVED,
            coverage=coverage,
            projection_status="projected",
        )
        append = await run_prepared_append(
            runtime.ledger,
            PreparedMutation(
                writer_id=binding.writer_id,
                operation_id=operation_id,
                request_digest=request_digest,
                expected_frontier=current.sequence,
                finalized_object_refs=(payload_ref,),
                command=AppendCommand(
                    task_id=parent_task_id,
                    session_id=binding.session_id,
                    writer_id=binding.writer_id,
                    operation_id=operation_id,
                    operation_kind=OperationKind.PUBLISH_WORK,
                    request_digest=request_digest,
                    expected_frontier=current.sequence,
                    entries=(entry,),
                ),
            ),
        )
        if len(append.accepted) != 1 or append.accepted[0].event_id != stable_event_id:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The delegation event could not be verified.",
                safe_details={"reason_code": "lineage_event_contradiction"},
            )
    finally:
        await app.runtime.release(runtime)


async def _delegated_result(
    app: _StartApplication,
    request: StartRequest,
    operation: DelegationOperation,
    handle: AttachHandle,
) -> StartInternalResult:
    parent_task_id = operation.parent_task_id
    parent_session_id = operation.parent_session_id
    binding = await app.start_catalog.session_binding(parent_session_id)
    if binding is None or binding.task_id != parent_task_id:
        route_lookup = getattr(app.start_catalog, "task_route", None)
        route = (
            await cast(Callable[[str], Awaitable[TaskRoute | None]], route_lookup)(parent_task_id)
            if callable(route_lookup)
            else None
        )
        if route is None:
            raise _error(PublicErrorCode.SESSION_NOT_FOUND, "The parent task was not found.")
        binding = await app.start_catalog.session_binding(route.session_id)
    if binding is None:
        raise _error(PublicErrorCode.SESSION_CONFLICT, "The parent session is no longer active.")
    runtime = await app.runtime.route(
        RouteCommand(
            binding.session_id,
            binding.writer_id,
            RouteAccess.PAYLOAD_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        frontier = await runtime.ledger.load_frontier()
        projection = await runtime.ledger.load_projection(
            runtime.session_id, ProjectionView.COMPACT
        )
        if projection is None or type(projection.state) is not tuple or len(projection.state) != 1:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The parent projection is unavailable.",
                safe_details={"reason_code": "projection_unavailable"},
            )
        item = projection.state[0]
        if type(item) is not StatusCompactItemModel:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The parent projection is unavailable.",
                safe_details={"reason_code": "projection_unavailable"},
            )
        compact = StartCompactViewModel.model_validate(
            {
                "coverage": item.coverage.model_dump(mode="json"),
                "current_plan_event_id": item.current_plan_event_id,
                "gaps": list(item.gaps),
                "ledger_freshness": item.freshness,
                "open_obligation_count": item.open_obligation_count,
                "unanswered_finding_count": item.unanswered_finding_count,
                "receipt_blocking_finding_count": item.receipt_blocking_finding_count,
            }
        )
        versions = StartVersionSliceModel.model_validate(
            {
                "engine_version": runtime.engine_version,
                "policy_packs": list(app.policy_packs),
                "projection_version": runtime.projection_version,
                "protocol_version": runtime.protocol_version,
            }
        )
    finally:
        await app.runtime.release(runtime)
    return StartInternalResult(
        protocol_version="0.1",
        schema_version="1.0.0",
        request_id=request.request_id,
        ok=True,
        outcome="delegated",
        task_id=operation.child_task_id,
        session_id=binding.session_id,
        writer_id=binding.writer_id,
        frontier=FrontierModel.model_validate(dict(frontier.as_wire())),
        compact=compact,
        versions=versions,
        attach_handle=handle,
        parent_task_id=parent_task_id,
        depth=operation.depth,
        origin=LineageOrigin.PARENT_MINTED,
        acceptance=LineageAcceptance.ACCEPTED,
    )


async def _execute_delegation(
    app: _StartApplication,
    request: StartRequest,
    repository_privacy_commitment: str | None,
) -> StartInternalResult:
    lineage = _lineage_for(app)
    if request.session_id is None:
        raise _invalid_request()
    # A retried delegation may arrive after the parent's host session rotated.  Resolve an
    # existing operation by its durable request identity first, then use the task's current route
    # for the parent event/result.  A fresh request still requires the exact active parent session.
    existing_operation = await lineage.store.get_operation(request.request_id)
    request_identity = request
    if existing_operation is None:
        route = await app.start_catalog.resolve_route(request.session_id)
        if route is None or route.state is not TaskRouteState.ACTIVE:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The parent session was not found.",
                safe_details={"reason_code": "lineage_parent_not_found"},
            )
        parent_task_id = route.task_id
        parent_session_id = request.session_id
    else:
        parent_task_id = existing_operation.parent_task_id
        parent_session_id = existing_operation.parent_session_id
        current_route = await app.start_catalog.resolve_route(request.session_id)
        if current_route is not None and current_route.task_id != parent_task_id:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The parent session is no longer active.",
                safe_details={"reason_code": "lineage_parent_session_invalid"},
            )
        if current_route is None and request.session_id != parent_session_id:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The parent session was not found.",
                safe_details={"reason_code": "lineage_parent_not_found"},
            )
        # The original delegation digest names the parent selector that minted the child.  Keep
        # that selector when rebuilding the idempotency digest, while the current session (when
        # available) remains the route used by the caller for this retry.  This permits recovery
        # after a host session rotation without allowing a different request body to replay the
        # operation.
        if request.session_id != parent_session_id:
            request_identity = request.model_copy(update={"session_id": parent_session_id})
        route_lookup = getattr(app.start_catalog, "task_route", None)
        route = (
            await cast(Callable[[str], Awaitable[TaskRoute | None]], route_lookup)(parent_task_id)
            if callable(route_lookup)
            else None
        )
        if route is None or route.state is TaskRouteState.QUARANTINED:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The parent task was not found.",
                safe_details={"reason_code": "lineage_parent_not_found"},
            )
    command = await _command(
        app,
        request,
        repository_privacy_commitment,
        request_identity=request_identity,
    )
    reservation = await lineage.reserve_delegation(
        DelegationRequest(
            operation_id=request.request_id,
            request_digest=command.request_digest,
            parent_task_id=parent_task_id,
            parent_session_id=parent_session_id,
            repository_commitment=repository_privacy_commitment,
            workspace_commitment=command.identity_commitments.workspace_ref_commitment,
            external_commitment=command.identity_commitments.external_ref_commitment,
        )
    )
    operation = reservation.operation
    if operation.phase is DelegationPhase.LINEAGE_RESERVED:
        await _provision_delegated_child(app, operation)
        operation = await lineage.mark_child_bundle_ready(
            operation.operation_id, operation.request_digest
        )
    if operation.phase is DelegationPhase.CHILD_BUNDLE_READY:
        await _append_delegation_event(app, operation)
        operation = await lineage.mark_parent_event_committed(
            operation.operation_id, operation.request_digest
        )
    if operation.phase is DelegationPhase.PARENT_EVENT_COMMITTED:
        reservation = await lineage.publish_attach_handle(
            operation.operation_id, operation.request_digest
        )
        operation = reservation.operation
    if operation.phase is DelegationPhase.HANDLE_PUBLISHED:
        reservation = await lineage.complete_delegation(
            operation.operation_id, operation.request_digest
        )
        operation = reservation.operation
    handle = await lineage.store.get_handle(operation.handle_digest)
    if handle is None:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The delegation handle is missing.",
            safe_details={"reason_code": "lineage_handle_missing"},
        )
    result = await _delegated_result(app, request, operation, handle)
    child = await lineage.store.get_task(operation.child_task_id)
    if child is None:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The delegated child is missing.",
            safe_details={"reason_code": "lineage_child_missing"},
        )
    await _merge_host_annotation(
        app,
        request,
        child,
        parent_session_id=operation.parent_session_id,
    )
    return result


async def recover_delegation(
    app: _StartApplication,
    operation: DelegationOperation,
) -> DelegationOperation:
    """Finish one reclaimed delegation operation without minting another child.

    Recovery uses the same phase helpers as the public ``start(mode=delegate)`` path.  Each
    helper is idempotent against its durable operation identity, so a crash after any external
    boundary can be retried by the next READY generation.  The operation row's lease was already
    reclaimed by ``LineageCoordinator.recover_delegations`` before this function is called.
    """

    if type(operation) is not DelegationOperation:
        raise TypeError("delegation_operation_invalid")
    lineage = _lineage_for(app)
    current = operation
    if current.phase is DelegationPhase.LINEAGE_RESERVED:
        await _provision_delegated_child(app, current)
        current = await lineage.mark_child_bundle_ready(
            current.operation_id, current.request_digest
        )
    if current.phase is DelegationPhase.CHILD_BUNDLE_READY:
        await _append_delegation_event(app, current)
        current = await lineage.mark_parent_event_committed(
            current.operation_id, current.request_digest
        )
    if current.phase is DelegationPhase.PARENT_EVENT_COMMITTED:
        await lineage.publish_attach_handle(current.operation_id, current.request_digest)
        current = await lineage.store.get_operation(current.operation_id) or current
    if current.phase is DelegationPhase.HANDLE_PUBLISHED:
        current = (
            await lineage.complete_delegation(current.operation_id, current.request_digest)
        ).operation
    return current


async def execute_start(
    app: _StartApplication,
    request: StartRequest,
    *,
    repository_privacy_commitment: str | None = None,
) -> StartInternalResult:
    """Route ordinary starts and the lineage admission paths through one facade."""

    if request.mode == "delegate":
        return await _execute_delegation(app, request, repository_privacy_commitment)
    if request.attach_handle is not None:
        return await _execute_handle_attach(app, request, repository_privacy_commitment)
    if request.parent_session_id is not None:
        return await _execute_self_registration(app, request, repository_privacy_commitment)
    return await _execute_standard_start(
        app,
        request,
        repository_privacy_commitment=repository_privacy_commitment,
    )
