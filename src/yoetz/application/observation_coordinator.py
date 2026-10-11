"""Service-level observation coordinator: local routing → task SQLite → ledger."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol, cast

from yoetz.adapters.approved_checks import ApprovedCheckRunner, ApprovedCheckStatus
from yoetz.adapters.git_subject_state import (
    GitSubjectStateAdapter,
    list_changed_relative_paths,
    open_local_workspace,
)
from yoetz.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    acquire_session_lock,
    load_mapping,
    load_route_history,
    store_mapping,
    validate_codex_session_id,
)
from yoetz.adapters.integrations.observation_local import (
    CaptureHandoffStructuralState,
    LocalContentCaptureAuthority,
    LocalObservationStore,
    session_commitment_from_codex_id,
)
from yoetz.adapters.workspace_inspect import LocalWorkspaceInspectAdapter
from yoetz.application.lineage_coordinator import LineageManifestCoordinator
from yoetz.application.observation_advice import (
    ADVICE_SEMANTIC_PENDING_GAP,
    ObservationAdviceContextBuilder,
    scoped_session_envelopes,
)
from yoetz.application.observation_advice_semantic import (
    AdviceSemanticCancellationReconciler,
    AdviceSemanticDispatch,
    AdviceSemanticDrainHandle,
    ObservationAdviceSemanticRepository,
    ObservationAdviceSemanticSupervisor,
    ObservationAdviceSemanticWorker,
)
from yoetz.application.observation_check_policy import (
    ObservationCheckPolicyAbsent,
    load_observation_check_policy,
)
from yoetz.application.observation_committed import (
    action_event_committed,
    observation_already_committed,
)
from yoetz.application.observation_drain import ObservationCaptureRecoveryOutcome
from yoetz.application.observation_materialize import (
    MATERIALIZATION_LEGACY_MAPPING_VERSIONS,
    MATERIALIZATION_MAPPING_VERSION,
    PAIRED_ACTION_ROLE,
    SESSION_BOUND_MAPPING_VERSIONS,
    MaterializedObservationBatch,
    PairedActionLink,
    approved_check_author,
    canonical_logical_identity,
    codex_stream_call_generation_links,
    materialize_capture_handoff_retirement,
    materialize_observation_envelope,
    materialize_observation_inspection_snapshot,
    materialize_observation_outcome_correction,
    materialize_selection_loss,
    media_type_for_schema,
    observation_author,
    observation_claim_identity,
    observation_content_identity,
    observation_event_ids_call_keyed,
    observation_operation_digest,
    observation_writer_id,
    paired_action_link,
    paired_action_linked_roles,
    stable_observation_id,
    stream_event_is_completed_tool,
)
from yoetz.application.observation_verification import (
    CompletedApprovedCheck,
    ObservationVerificationJob,
    ObservationVerificationRepository,
    ObservationVerificationSupervisor,
    ObservationVerificationWorker,
    VerificationDrainHandle,
    orchestrate_changed_path_inspection,
)
from yoetz.application.projects import SourceConsentRevocationPlan
from yoetz.application.unit_of_work import (
    PreparedMutation,
    PreSubmissionCancelled,
    abandon_preappend_objects,
    run_prepared_append,
)
from yoetz.domain.events import (
    EVIDENCE_TYPED_SCHEMA_VERSION,
    SEMANTIC_EVENT_SCHEMA_VERSION,
    ActionKind,
    ActionRecordedPayload,
    EventDraft,
    EventSchema,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingId,
    FindingKind,
    FindingOrigin,
)
from yoetz.domain.host_lineage import (
    HostLineageObservation,
    host_lineage_from_envelope,
    host_lineage_from_payload,
)
from yoetz.domain.observation import (
    CAPTURE_HANDOFF_RECONCILE_AGE_MS,
    OBSERVATION_BACKPRESSURE_REASON,
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    AdviceItem,
    CaptureHandoffRetirementReason,
    CaptureHandoffRetirementStage,
    ObservationCapturePart,
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationContentManifest,
    ObservationControlCommand,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationInspectionSnapshot,
    ObservationRevokeCommand,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
    observation_capture_part_descriptors,
    observation_capture_ticket_id,
    observation_content_binding_matches,
    observation_envelope_to_json,
    observation_selection_route,
    observation_source_qualified_content_binding_matches,
)
from yoetz.domain.observation_loss import ObservationSelectionLoss
from yoetz.domain.observation_profiles import content_capture_profile_matches_source
from yoetz.domain.values import (
    Frontier,
    JsonObject,
    SubjectStateRef,
    Timestamp,
    action_id,
    event_id,
    evidence_id,
    frontier_from_json,
    object_id,
    result_id,
    timestamp_from_datetime,
    timestamp_from_string,
)
from yoetz.kernel.projections import ProjectionRecord, ProjectionState
from yoetz.observability.logging import record_unexpected_exception_without_raising
from yoetz.observability.privacy import prepare_persisted_plaintext
from yoetz.ports.clock import ClockPort
from yoetz.ports.host_lineage import (
    HostLineageRegistryError,
    HostLineageRegistryPort,
    HostLineageRegistryReason,
)
from yoetz.ports.ids import IdPort
from yoetz.ports.ledger import (
    AcceptedEventSummary,
    AppendCommand,
    AppendEntry,
    AppendResult,
    AppendWarning,
    OperationKind,
    OperationRecord,
    OperationState,
    ProjectionView,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource, StagedObject
from yoetz.ports.observation import ObservationLogicalIdentityClaim, TaskObservationPort
from yoetz.ports.runtime import (
    BundleRuntimePort,
    RouteAccess,
    RouteCommand,
    RuntimeCapability,
    TaskRuntime,
)
from yoetz.ports.subject_state import SubjectStateCaptureCommand, SubjectStateFormat
from yoetz.ports.workspace_inspect import InspectedArtifact
from yoetz.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from yoetz.protocol.coverage import EvidenceImmutability, PublicationChannel, coverage_for_channel
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, is_valid_id
from yoetz.protocol.policy_packs import CURRENT_POLICY_VERSIONS

_ADVICE_FINDING_KIND_BY_RULE: Final = MappingProxyType(
    {
        "failed_command_unresolved": FindingKind.FAILED_WORK_OMITTED,
        "edit_after_successful_check": FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
        "completion_without_verification": FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        "static_test_for_live_claim": FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
        "subagent_finding_unaddressed": FindingKind.MATERIAL_LIMITATION_OMITTED,
        "change_outside_plan": FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
        "observation_gap_or_stale": FindingKind.LEDGER_STALE_OR_INCOMPLETE,
        "semantic_claim_without_attempt": FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
    }
)

_LEGACY_UNPAIRED_REPLAY_PROFILE: Final = "legacy-paired-replay"
# How many recent hook generations a post-compaction stream completion may search for its
# hook call (#1019). Each Codex SessionStart (compact, resume, clear) is one generation.
_CODEX_GENERATION_ALIAS_WINDOW: Final = 16
_CAPTURED_CONTENT_MEDIA_TYPE: Final = "application/vnd.yoetz.observation-content+json"
# This is the coordinator-side upper-bound guard for the central local-store
# reservation. Keep it equal to the local capture fence: the reservation is
# acquired before object staging, while the task SQLite store repeats the
# actual manifest-byte check at its durable boundary.
_MAX_CAPTURE_CONTENT_BYTES: Final = 128 * 1024 * 1024
_MAX_CAPTURE_BOOTSTRAP_WORKSPACES: Final = 256
# One maintenance turn opens at most this many task routes for aged handoffs.
# A bounded cursor rotates through the deterministic oldest-first candidate list
# so unavailable early routes cannot starve later ones (#836).
_MAX_CAPTURE_HANDOFF_TASKS_PER_TURN: Final = 8
# ``SqliteObservationStore.list_pending_capture_tickets`` caps one task route
# at the same bound. A result below the cap is the only listing we can treat as
# complete for pending-account confirmation.
_MAX_CAPTURE_TICKETS_PER_TASK: Final = 512
_CAPTURE_TICKET_RETRYABLE_REJECTION_REASONS: Final = frozenset(
    {
        OBSERVATION_BACKPRESSURE_REASON,
        OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
        ObservationGapCode.VAULT_LOCKED.value,
        ObservationGapCode.MAPPING_MISSING.value,
        "observation_disabled",
        "paused",
    }
)


@dataclass(frozen=True, slots=True)
class _NativeCaptureContext:
    native_source: bool
    requested_content_profile: str | None
    content_identity: str | None
    pending_capture_ticket: ObservationCaptureTicket | None
    content_authorized: bool
    content_authorization_missing: bool
    content_capture_blocked: bool
    capture_ticket_revoked: bool
    native_content_requested: bool
    capture_fence: Callable[[], Awaitable[bool]] | None
    fence_generation: str | None
    capture_staging_ticket: ObservationCaptureTicket | None
    staged_ticket: ObservationCaptureTicket | None
    expected_capture_parts: tuple[ObservationCapturePart, ...] | None
    rejection_reason: str | None


def _legacy_unpaired_replay_envelope(
    envelope: ObservationEnvelope,
) -> ObservationEnvelope | None:
    """Return a synthetic pre-#607 pairing view for historical role recovery.

    Before host/profile pairing was explicit, every post with an unpaired gap
    materialized as ``unpaired_evidence``. A current Claude/Cursor profile can
    materialize the same retained envelope as a post-only action/result, so
    retries need the old role set while probing pre-1.6 operation identities.
    The synthetic profile is never persisted or sent across the wire.
    """

    if ObservationGapCode.UNPAIRED_EVENT.value not in envelope.gap_codes:
        return None
    structural = dict(envelope.structural_payload)
    structural.update(
        {
            "capability_profile_id": _LEGACY_UNPAIRED_REPLAY_PROFILE,
            "pairing_mode": "paired",
            "correlation_kind": "tool_call_id",
        }
    )
    return replace(envelope, structural_payload=JsonObject(structural))


def _materialized_advice_items(items: Sequence[AdviceItem]) -> tuple[AdviceItem, ...]:
    """Keep advice that describes repairable work; machine conditions remain advice only."""

    return tuple(
        item
        for item in items
        if item.origin == "deterministic" and item.rule_code in _ADVICE_FINDING_KIND_BY_RULE
    )


def _append_result_from_committed(record: object) -> AppendResult | None:
    """Rebuild frontier metadata from a completed append so retry can note motion."""

    if type(record) is not OperationRecord:
        return None
    if record.state is not OperationState.COMPLETE or record.result_canonical is None:
        return None
    try:
        parsed = strict_json_parse(record.result_canonical)
    except ProtocolValueError, TypeError, ValueError:
        return None
    if not isinstance(parsed, Mapping):
        return None
    result_map = cast(Mapping[str, object], parsed)
    accepted_raw = result_map.get("accepted")
    if not isinstance(accepted_raw, list | tuple) or not accepted_raw:
        return None
    try:
        accepted = tuple(
            AcceptedEventSummary(
                cast(str, item["event_id"]),
                int(cast(str, item["ingestion_sequence"])),
                int(cast(str, item["writer_sequence"])),
                cast(str, item["entry_digest"]),
                cast(
                    Literal["projected", "unknown_unprojected"],
                    item["projection_status"],
                ),
            )
            for item in cast(tuple[Mapping[str, object], ...], accepted_raw)
        )
        warnings_raw = result_map.get("warnings") or ()
        warnings = tuple(
            AppendWarning(cast(str, value)) for value in cast(tuple[object, ...], warnings_raw)
        )
        return AppendResult(
            "replayed",
            accepted,
            frontier_from_json(result_map["subject_frontier"]),
            frontier_from_json(result_map["result_frontier"]),
            warnings,
        )
    except KeyError, ProtocolValueError, TypeError, ValueError:
        return None


def _selection_loss_operation_digest(
    loss: ObservationSelectionLoss, *, quarantined_recovery: bool = False
) -> str:
    """Return the stable operation identity for one loss marker.

    A quarantined append operation is terminal.  It must not be retried under the
    same operation id, but a fresh task-scoped marker can still report the retained
    loss when the ledger is otherwise writable.
    """

    value: dict[str, str] = {
        "format": "yoetz.selection-loss-report/1",
        "task_id": loss.task_id,
        "lane": loss.lane,
    }
    if quarantined_recovery:
        value["recovery"] = "quarantined"
    return canonical_digest(JsonObject(value))


__all__ = [
    "ObservationAdviceHook",
    "ObservationCoordinator",
    "ObservationMappingLoader",
    "ObservationMappingStorer",
    "build_inspection_excerpt_manifest",
]

# One catalog lookup already returns the current task binding. Extra hops cover a
# rotation that lands between the superseded error and the retry (#577).
_MAX_SUPERSEDED_ROUTE_HOPS: Final = 4

_INSPECT_EXCERPT_FORMAT: Final = "yoetz.observation-inspect-excerpt/1"
_MAX_INSPECT_EXCERPT_ARTIFACTS: Final = 16
_MAX_INSPECT_EXCERPT_PREFIX_BYTES: Final = 512


def build_inspection_excerpt_manifest(
    artifacts: Sequence[InspectedArtifact],
    *,
    canaries: tuple[bytes, ...] = (),
) -> tuple[bytes | None, bool, bool, bool]:
    """Scan changed-file excerpts before base64 encoding.

    Returns ``(canonical_bytes, capture_unavailable, redacted, truncated)``. High-confidence
    secret matches persist only path/digest/finding-kind metadata; heuristic-only matches are
    kept in the encrypted excerpt and redacted at egress (issue #982). A scanner failure or
    canary match stores no excerpt object. Redaction and truncation remain explicit coverage
    limitations without requiring a later consumer to reopen captured bytes.
    """

    parts: list[JsonObject] = []
    capture_unavailable = False
    redacted = False
    truncated = False
    seen = 0
    for item in artifacts:
        if type(item) is not InspectedArtifact:
            continue
        if seen >= _MAX_INSPECT_EXCERPT_ARTIFACTS:
            break
        seen += 1
        if not item.excerpt:
            continue
        prefix = item.excerpt[:_MAX_INSPECT_EXCERPT_PREFIX_BYTES]
        item_truncated = item.excerpt_truncated or len(item.excerpt) > len(prefix)
        truncated = truncated or item_truncated
        scan = prepare_persisted_plaintext(prefix, canaries=canaries)
        if not scan.persist:
            capture_unavailable = True
            break
        if scan.redacted:
            redacted = True
            parts.append(
                JsonObject(
                    {
                        "path": item.relative_path,
                        "digest": item.content_digest,
                        "redacted": True,
                        "excerpt_truncated": item_truncated,
                        "byte_length": item.byte_length,
                        "finding_kinds": list(scan.finding_kinds),
                    }
                )
            )
            continue
        parts.append(
            JsonObject(
                {
                    "path": item.relative_path,
                    "digest": item.content_digest,
                    "redacted": False,
                    "excerpt_truncated": item_truncated,
                    "byte_length": item.byte_length,
                    "excerpt_b64": base64.b64encode(scan.content).decode("ascii"),
                }
            )
        )
    if capture_unavailable:
        return None, True, redacted, truncated
    if not parts:
        return None, False, redacted, truncated
    return (
        canonical_encode(JsonObject({"format": _INSPECT_EXCERPT_FORMAT, "artifacts": parts})),
        False,
        redacted,
        truncated,
    )


class ObservationMappingLoader(Protocol):
    def __call__(
        self, codex_session_id: str, *, _state: Path | None = None
    ) -> LifecycleMapping | None: ...


class ObservationMappingStorer(Protocol):
    def __call__(self, mapping: LifecycleMapping, *, _state: Path | None = None) -> None: ...


class ObservationConsentInvalidationPlanner(Protocol):
    def __call__(
        self, task_ids: tuple[str, ...], workspace_commitment: str, revocation_token: str
    ) -> Awaitable[SourceConsentRevocationPlan]: ...


class ObservationConsentInvalidationApplier(Protocol):
    def __call__(self, plan: SourceConsentRevocationPlan) -> Awaitable[object]: ...


def _session_superseded_binding(
    error: PublicOperationError, *, expected_task_id: str
) -> tuple[str, str] | None:
    """Return successor session/writer ids when the public error carries the current binding."""

    if error.code is not PublicErrorCode.SESSION_NOT_FOUND:
        return None
    details = error.safe_details
    if details.get("reason_code") != "session_superseded":
        return None
    task_id = details.get("task_id")
    session_id = details.get("session_id")
    writer_id = details.get("writer_id")
    if (
        type(task_id) is not str
        or type(session_id) is not str
        or type(writer_id) is not str
        or task_id != expected_task_id
        or not is_valid_id(IdKind.TASK, task_id)
        or not is_valid_id(IdKind.SESSION, session_id)
        or not is_valid_id(IdKind.WRITER, writer_id)
    ):
        return None
    return session_id, writer_id


def _observation_writer_routes(
    runtime: TaskRuntime,
    route_history: Sequence[LifecycleMapping],
    *,
    state_root: Path | None,
) -> tuple[tuple[tuple[str, str], ...], bool]:
    """Return the bounded writer routes admitted during one observation request.

    A start operation records its cooperative writer in the lifecycle mapping,
    while observation materialization historically used the deterministic
    observation writer for the same ``(task, session)`` pair.  Both identities
    remain valid for replay, and a session retirement can leave several such
    pairs behind before the request reaches its current route.  Keep the route
    order stable and remove duplicates so the legacy probe is deterministic.
    """

    candidates: list[tuple[str, str]] = []
    if runtime.writer_id is not None:
        candidates.append((runtime.session_id, runtime.writer_id))
    for mapping in route_history:
        candidates.extend(
            (
                (mapping.yoetz_session_id, mapping.yoetz_writer_id),
                (
                    mapping.yoetz_session_id,
                    observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
                ),
            )
        )
    # A prior route may have been cached by a previous process before this
    # request started.  Keep it in the same bounded candidate list as the
    # request-local hops; the sidecar is task-filtered by the lifecycle adapter.
    history_truncated = False
    if route_history:
        current = route_history[-1]
        durable_history = load_route_history(current, _state=state_root)
        if durable_history is None:
            raise PublicOperationError(
                PublicErrorCode.STORAGE_CORRUPT,
                "Observation route history is invalid.",
                retryable=False,
            )
        history_truncated = durable_history.truncated
        for session_id, writer_id in durable_history.routes:
            candidates.extend(
                (
                    (session_id, writer_id),
                    (session_id, observation_writer_id(current.yoetz_task_id, session_id)),
                )
            )
    return tuple(dict.fromkeys(candidates)), history_truncated


@dataclass(frozen=True, slots=True)
class _ActionLinkPlan:
    """Which phase of a paired host call appends its single action (#917)."""

    link: PairedActionLink | None
    batch: MaterializedObservationBatch
    skip: bool
    role_sets: tuple[tuple[str, ...], ...]

    def same_content_roles(self, resolved: tuple[str, ...], current: tuple[str, ...]) -> bool:
        """Whether a committed role set differs from this batch only by the linked action."""

        if resolved == current:
            return True
        return self.link is not None and paired_action_linked_roles(
            resolved
        ) == paired_action_linked_roles(current)


@dataclass(frozen=True, slots=True)
class _AlreadyCommitted:
    """An observation whose every event the task ledger already holds (#1027).

    The append found no committed operation under any role-set shape it could reconstruct, but
    each event id of the batch is already recorded, so appending would only be refused. The
    delivery is a duplicate of an earlier one (a hook copy and a stream copy of one call, or a
    content-bearing and a contentless copy): nothing is appended, and a stream copy's explicit
    outcome is still applied to the recorded action.
    """

    event_ids: frozenset[str]


def _load_logical_identity_claim(
    store: TaskObservationPort,
    *,
    workspace: str,
    logical_identity: str,
) -> ObservationLogicalIdentityClaim | None:
    """Read one optional durable claim without widening test-only store seams."""

    loader = getattr(store, "load_logical_identity_claim", None)
    if not callable(loader):
        return None
    raw_claim = loader(workspace=workspace, logical_identity=logical_identity)
    if raw_claim is None:
        return None
    if type(raw_claim) is not tuple:
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT,
            "Observation logical identity claim is invalid.",
            retryable=False,
        )
    claim_values = cast(tuple[object, ...], raw_claim)
    if len(claim_values) != 3 or not all(type(value) is str for value in claim_values):
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT,
            "Observation logical identity claim is invalid.",
            retryable=False,
        )
    materialization_digest = cast(str, claim_values[0])
    operation_id = cast(str, claim_values[1])
    mapping_version = cast(str, claim_values[2])
    if (
        len(materialization_digest) != 71
        or not materialization_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in materialization_digest[7:])
        or not is_valid_id(IdKind.REQUEST, operation_id)
        or mapping_version
        not in {MATERIALIZATION_MAPPING_VERSION, *MATERIALIZATION_LEGACY_MAPPING_VERSIONS}
    ):
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT,
            "Observation logical identity claim is invalid.",
            retryable=False,
        )
    return cast(ObservationLogicalIdentityClaim, raw_claim)


class ObservationAdviceHook(Protocol):
    """Optional post-commit advice hook for the advice/health agent."""

    def __call__(
        self,
        *,
        workspace_commitment: str,
        task_id: str,
        store: TaskObservationPort,
        envelopes: tuple[ObservationEnvelope, ...],
        frontier: str | None,
    ) -> Awaitable[None] | None: ...


class CaptureBudgetBootstrapHook(Protocol):
    """Ready-owned complete task inventory for native capture admission."""

    def __call__(
        self, workspace: str, runtime: TaskRuntime, store: TaskObservationPort, /
    ) -> Awaitable[bool]: ...


type CaptureHandoffVisitor = Callable[[TaskRuntime, TaskObservationPort], Awaitable[int]]


class CaptureHandoffReconcileHook(Protocol):
    """Ready-owned routing of the tasks that own aged native capture handoffs.

    The callback opens each named task route through the service catalog,
    applies ``visit`` to its runtime and observation store, and releases it.
    It needs no host-session mapping, so a handoff left by an ended session is
    still reachable.  It returns ``True`` only when every named task was
    visited.  The coordinator invokes it while holding the shared capture lock
    (#836).
    """

    def __call__(
        self,
        workspace: str,
        task_ids: tuple[str, ...],
        visit: CaptureHandoffVisitor,
        /,
    ) -> Awaitable[bool]: ...


def _capture_handoff_retirement_reason(
    ticket: ObservationCaptureTicket,
    authority: LocalContentCaptureAuthority | None,
    structural: CaptureHandoffStructuralState | None,
    *,
    age_ms: int,
) -> tuple[CaptureHandoffRetirementReason, str | None] | None:
    """Decide whether an unfinished handoff can still be consumed.

    Current local content authority is required first; those rules match the
    CHECK preflight.  With ``structural`` supplied, an aged handoff is kept only
    while an outbox row or selected input with its exact native identity can
    still be delivered.  A missing row cannot come back: only the row itself
    consumes a ticket, and the drain acknowledges or quarantines it only after
    the coordinator has returned.  Returns the reason and, for a quarantined
    row, its closed quarantine reason.
    """

    if authority is None:
        return CaptureHandoffRetirementReason.AUTHORITY_ABSENT, None
    if not authority.active:
        return CaptureHandoffRetirementReason.AUTHORITY_INACTIVE, None
    if not authority.runtime_enabled:
        return CaptureHandoffRetirementReason.RUNTIME_DISABLED, None
    if ticket.authority_generation != authority.generation:
        return CaptureHandoffRetirementReason.AUTHORITY_GENERATION_CHANGED, None
    if (
        ticket.content_capture_profile is not None
        and ticket.content_capture_profile not in authority.profiles
    ):
        return CaptureHandoffRetirementReason.PROFILE_UNSELECTED, None
    if structural is None or age_ms < CAPTURE_HANDOFF_RECONCILE_AGE_MS:
        return None
    key = (ticket.source.value, ticket.session_commitment, ticket.source_identity)
    if key in structural.pending:
        return None
    quarantine_reason = structural.quarantined.get(key)
    if quarantine_reason is not None:
        return CaptureHandoffRetirementReason.STRUCTURAL_ROW_QUARANTINED, quarantine_reason
    return CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT, None


def _native_child_start_observation(envelope: ObservationEnvelope) -> HostLineageObservation | None:
    fields = envelope.structural_payload
    return host_lineage_from_payload(
        "codex",
        "SubagentStart",
        {key: fields[key] for key in ("subagent_id", "parent_tool_call_id") if key in fields},
    )


def _reject(reason: str, cursor: object | None = None) -> ObservationIngestResult:
    return ObservationIngestResult(
        ObservationIngestDisposition.REJECTED,
        reason,
        cast(Any, cursor),
    )


def _selection_route_is_current(
    route: tuple[str, str, str, str],
    runtime: TaskRuntime,
    legacy_writer_routes: Sequence[tuple[str, str]],
    *,
    authority_generation: str | None,
    authority_active: bool,
) -> bool:
    """Keep a selected row bound to its task, route lineage, and authority.

    The host session commitment authenticates the native source, but it does
    not distinguish a durable row buffered before a session/task rebind.  A
    selected row therefore carries its Yoetz route explicitly.  Historical
    session/writer pairs remain valid for same-task replay; a different task
    or authority generation is rejected before store ingest advances a cursor.
    """

    selected_task, selected_session, selected_writer, selected_generation = route
    if selected_task != runtime.task_id or not authority_active:
        return False
    if authority_generation != selected_generation:
        return False
    admitted_routes = set(legacy_writer_routes)
    if runtime.writer_id is not None:
        admitted_routes.add((runtime.session_id, runtime.writer_id))
    return (selected_session, selected_writer) in admitted_routes


class _StructuralCaptureHandoff:
    """The native row a structural delivery carries, once its capture fence resolved.

    Only this row can consume a durable handoff bound to its content identity,
    so a delivery that commits or is refused terminally retires any handoff it
    leaves behind (#836). A capture-only request stages handoffs and never binds.
    """

    __slots__ = ("content_identity", "envelope")

    def __init__(self) -> None:
        self.envelope: ObservationEnvelope | None = None
        self.content_identity: str | None = None

    def bind(self, request: ObservationIngestRequest, capture: _NativeCaptureContext) -> None:
        if not request.capture_only and capture.content_identity is not None:
            self.envelope = request.envelope
            self.content_identity = capture.content_identity


def _empty_advice_event_ref_cache() -> dict[tuple[str, str], tuple[str, ...]]:
    return {}


def _empty_storage_corrupt_sessions() -> set[str]:
    return set()


def _empty_capture_bootstrap_workspaces() -> set[str]:
    return set()


@dataclass
class ObservationCoordinator:
    """Resolve Codex session → mapped task SQLite observation store + ledger."""

    runtime: BundleRuntimePort
    local: LocalObservationStore
    clock: ClockPort
    ids: IdPort
    mapping_loader: ObservationMappingLoader = load_mapping
    mapping_storer: ObservationMappingStorer = store_mapping
    state_root: Path | None = None
    advice_hook: ObservationAdviceHook | None = None
    # READY binds these to ProjectApplication. The planner snapshots current project
    # generations; the applier performs the CAS-style fence and is replay-safe across restart.
    consent_invalidation_planner: ObservationConsentInvalidationPlanner | None = None
    consent_invalidation_applier: ObservationConsentInvalidationApplier | None = None
    advice_context_builder: ObservationAdviceContextBuilder = field(
        default_factory=ObservationAdviceContextBuilder
    )
    verification_supervisor: ObservationVerificationSupervisor | None = None
    # Off-hook AI-powered advice (#619): the build only enqueues a durable row; this supervisor
    # drains it through ``advice_semantic_dispatch`` and re-runs advice when it finishes.
    advice_semantic_supervisor: ObservationAdviceSemanticSupervisor | None = None
    advice_semantic_dispatch: AdviceSemanticDispatch | None = None
    # Shielded post-cancellation reconciliation for a dispatch that already consumed a
    # disclosure authorization; it reports the terminal unknown receipt and never redispatches.
    advice_semantic_cancellation_reconciler: AdviceSemanticCancellationReconciler | None = None
    observation_enabled: bool = True
    capture_budget_bootstrap: CaptureBudgetBootstrapHook | None = None
    # READY routes the tasks that own aged native handoffs so maintenance can
    # retire one whose structural row is gone (#836). Without it only the
    # routed mapping's own task is reconciled.
    capture_handoff_reconcile: CaptureHandoffReconcileHook | None = None
    lineage_coordinator: LineageManifestCoordinator | None = None
    # Host observations are recorded in the service-owned catalog after local ingest accepts the
    # envelope. The registry is optional for pre-migration/test compositions.
    host_lineage_registry: HostLineageRegistryPort | None = None
    # Receives the authenticated host commitment only after the active task/session route has
    # been selected.  Recovery uses this exact binding to fence predecessor annotations.
    observed_host_session_binding: Callable[[str, str, str], Awaitable[None]] | None = None
    # Receives ``(task_id, session_id, writer_id, observed_at)``; lineage decides what the
    # evidence proves at ``observed_at``.  The age bound only drops evidence too old to postpone
    # any recorded contact loss: the session lease plus the longest configurable recovery window.
    observed_activity_hook: Callable[[str, str, str, datetime], Awaitable[None]] | None = None
    observed_activity_max_age_seconds: int = 86_400 + 60
    _advice_event_ref_cache: dict[tuple[str, str], tuple[str, ...]] = field(
        default_factory=_empty_advice_event_ref_cache, init=False, repr=False
    )
    _storage_corrupt_sessions: set[str] = field(
        default_factory=_empty_storage_corrupt_sessions, init=False, repr=False
    )
    _local_executor: ThreadPoolExecutor | None = field(default=None, init=False, repr=False)
    _pending_releases: set[asyncio.Future[None]] = field(
        default_factory=lambda: set[asyncio.Future[None]](), init=False, repr=False
    )
    _capture_budget_exhausted: bool = field(default=False, init=False, repr=False)
    # A persisted root proof belongs to an older service generation until the
    # current coordinator has revalidated its route scope under the capture
    # lock.  Keep this fence process-local so restart/upgrade cannot reuse an
    # old proof without a fresh authoritative read.
    _capture_recovery_sessions: dict[str, str] = field(
        default_factory=lambda: dict[str, str](), init=False, repr=False
    )
    _selection_loss_after: dict[str, str] = field(
        default_factory=lambda: dict[str, str](), init=False, repr=False
    )
    _capture_handoff_after: dict[str, str] = field(
        default_factory=lambda: dict[str, str](), init=False, repr=False
    )
    _capture_bootstrap_verified_workspaces: set[str] = field(
        default_factory=_empty_capture_bootstrap_workspaces, init=False, repr=False
    )

    async def _local[ResultT](self, call: Callable[[], ResultT]) -> ResultT:
        """Run one blocking local-store call off the service event loop.

        Every ``LocalObservationStore`` entry point takes the same potentially blocking
        cross-process flock, so a read is no safer on the loop than a write. Reads route through
        this dedicated bounded pool too; the store also bounds acquisition so cancellation cannot
        leave a worker parked indefinitely (#238). The reentrant thread lock is acquired and
        released inside one worker on each hop, so no lock is held across an await.
        """

        executor = self._local_executor
        if executor is None:
            executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="yoetz-obs-local")
            self._local_executor = executor
        return await asyncio.get_running_loop().run_in_executor(executor, call)

    async def _publish_capture_backlog(
        self,
        workspace: str,
        runtime: TaskRuntime,
        store: TaskObservationPort,
    ) -> None:
        """Publish bounded task-local capture pressure after a store mutation.

        The SQLite read happens only after its caller's transaction has
        returned. The local update then takes the owner-private store lock in
        its own worker hop, so no SQLite/local lock inversion can be created.
        This is feedback only: an unavailable read records an unknown route
        when possible and never turns a failed cache update into a ledger
        failure.
        """

        updater = getattr(self.local, "update_capture_backlog", None)
        if not callable(updater):
            return
        reader = getattr(store, "capture_backlog", None)
        if not callable(reader):
            reader = getattr(store, "capture_ticket_backlog", None)
        try:
            raw_now = cast(object, self.clock.now_utc())
            observed_at = (
                raw_now if type(raw_now) is Timestamp else timestamp_from_datetime(raw_now)
            )
        except Exception:
            # Reference coordinators may omit a service clock. Feedback is
            # optional and must never turn a durable ingest into a failure.
            return
        backlog = None
        count = 0
        byte_count = 0
        oldest_receipt_time: Timestamp | None = None
        if callable(reader):
            try:
                backlog = reader(workspace)
                count = getattr(backlog, "count")
                byte_count = getattr(backlog, "byte_count")
                oldest_receipt_time = getattr(backlog, "oldest_receipt_time")
                if (
                    type(count) is not int
                    or isinstance(count, bool)
                    or count < 0
                    or type(byte_count) is not int
                    or isinstance(byte_count, bool)
                    or byte_count < 0
                    or (
                        oldest_receipt_time is not None
                        and type(oldest_receipt_time) is not Timestamp
                    )
                ):
                    raise TypeError("capture_backlog_shape_invalid")
            except Exception:
                # A stale/failed task read must not look like an empty global
                # backlog. Preserve the conservative unknown scope below.
                backlog = None
        if backlog is None:
            route_id = None
        else:
            route_id = runtime.task_id
        try:
            await self._local(
                partial(
                    updater,
                    workspace,
                    count,
                    byte_count,
                    oldest_receipt_time,
                    observed_at,
                    route_id=route_id,
                )
            )
        except TypeError:
            # Small reference adapters may still expose the pre-route form of
            # this private feedback hook. Keep those adapters conservative by
            # retrying without a route identity, which latches unknown scope.
            try:
                await self._local(
                    partial(
                        updater,
                        workspace,
                        count,
                        byte_count,
                        oldest_receipt_time,
                        observed_at,
                    )
                )
            except Exception:
                return
        except Exception:
            return
        await self._reconcile_capture_ticket_reservations(workspace, runtime, store)

    def _remember_capture_bootstrap(self, workspace: str) -> None:
        """Cache only a successfully validated inventory for this service generation."""

        if (
            workspace not in self._capture_bootstrap_verified_workspaces
            and len(self._capture_bootstrap_verified_workspaces)
            >= _MAX_CAPTURE_BOOTSTRAP_WORKSPACES
        ):
            self._capture_bootstrap_verified_workspaces.clear()
        self._capture_bootstrap_verified_workspaces.add(workspace)

    async def reconcile_task_selection_losses(self, runtime: TaskRuntime) -> None:
        """Before a new CHECK, publish only losses already bound to this task.

        Transient failures retain the exact lane and fail the new check closed.
        A terminal route drift or quarantined marker operation uses the supplied
        task runtime to publish the same historical marker without rebinding the
        loss to another task. Completed or already-frozen check requests bypass
        this hook and keep their result.
        """

        workspaces = await self._local(
            partial(self.local.selection_loss_workspaces, runtime.task_id)
        )
        for workspace in workspaces:
            await self._reconcile_selection_losses(
                workspace,
                task_id=runtime.task_id,
                fallback_runtime=runtime,
            )

    async def _append_selection_loss_marker(
        self,
        runtime: TaskRuntime,
        loss: ObservationSelectionLoss,
        batch: MaterializedObservationBatch,
        operation_digest: str,
    ) -> AppendResult | None:
        """Append a loss marker, recovering once from a quarantined operation.

        A pending operation remains retryable and a completed operation is decoded
        as-is.  Only a terminally quarantined marker gets a distinct deterministic
        operation identity; this preserves idempotency while preventing one
        malformed historical append from permanently blocking its task's checks.
        """

        writer_id = runtime.writer_id
        if writer_id is None:
            return None
        operation_id = self._stable_operation_id(operation_digest)
        existing = await runtime.ledger.lookup_task_operation(writer_id, operation_id)
        if existing is None:
            return await self._append_structural_batch(runtime, batch, operation_digest)
        if existing.request_digest != operation_digest:
            raise PublicOperationError(
                PublicErrorCode.IDEMPOTENCY_CONFLICT,
                "Observation loss operation identity conflicts with stored history.",
                retryable=False,
            )
        if existing.state is OperationState.COMPLETE:
            committed = _append_result_from_committed(existing)
            if committed is None:
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Stored observation loss operation cannot be replayed.",
                    retryable=False,
                )
            return committed
        if existing.state is OperationState.PENDING:
            raise PublicOperationError(
                PublicErrorCode.OPERATION_PENDING,
                "Observation loss reporting is still pending.",
                retryable=True,
            )

        recovery_digest = _selection_loss_operation_digest(loss, quarantined_recovery=True)
        recovery_id = self._stable_operation_id(recovery_digest)
        recovery = await runtime.ledger.lookup_task_operation(writer_id, recovery_id)
        if recovery is not None:
            if recovery.request_digest != recovery_digest:
                raise PublicOperationError(
                    PublicErrorCode.IDEMPOTENCY_CONFLICT,
                    "Observation loss recovery identity conflicts with stored history.",
                    retryable=False,
                )
            if recovery.state is OperationState.COMPLETE:
                committed = _append_result_from_committed(recovery)
                if committed is None:
                    raise PublicOperationError(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Stored observation loss recovery cannot be replayed.",
                        retryable=False,
                    )
                return committed
            if recovery.state is OperationState.PENDING:
                raise PublicOperationError(
                    PublicErrorCode.OPERATION_PENDING,
                    "Observation loss recovery is still pending.",
                    retryable=True,
                )
            raise PublicOperationError(
                PublicErrorCode.STORAGE_CORRUPT,
                "Observation loss recovery is quarantined.",
                retryable=False,
            )
        return await self._append_structural_batch(runtime, batch, recovery_digest)

    async def _reconcile_selection_losses(
        self,
        workspace: str,
        *,
        task_id: str | None = None,
        fallback_runtime: TaskRuntime | None = None,
    ) -> None:
        reports = await self._local(partial(self.local.pending_selection_losses, workspace))
        if not reports:
            return
        reports = tuple(sorted(reports, key=lambda item: str(item["lane"])))
        if task_id is None:
            after = self._selection_loss_after.get(workspace, "")
            reports = tuple(item for item in reports if str(item["lane"]) > after) + tuple(
                item for item in reports if str(item["lane"]) <= after
            )
            reports = reports[:8]
        # At most 64 durable lanes exist per workspace. No whole transcript or
        # input content is read and no native admission/capture path is invoked.
        for report in reports:
            try:
                route = observation_selection_route(report.get("route"))
                if task_id is not None and (route is None or route[0] != task_id):
                    continue
                loss = ObservationSelectionLoss.from_local_range_for_recovery(report)
            except ProtocolValueError, TypeError, ValueError:
                # A malformed route cannot be safely attributed to a task. A
                # route-valid range is normalized by the recovery constructor;
                # only the remaining unrouteable state stays local.
                continue
            if task_id is None:
                if (
                    workspace not in self._selection_loss_after
                    and len(self._selection_loss_after) >= 256
                ):
                    self._selection_loss_after.pop(next(iter(self._selection_loss_after)))
                self._selection_loss_after[workspace] = loss.lane
            current: TaskRuntime | None = None
            current_is_owned = False
            try:
                async with self._lock:
                    try:
                        current = await self._route_selection_loss(loss)
                        current_is_owned = True
                        if current.task_id != loss.task_id:
                            await self.runtime.release(current)
                            current = None
                            current_is_owned = False
                            raise ValueError("selection_loss_route_changed")
                    except (PublicOperationError, ValueError) as exc:
                        # A non-retryable route failure is terminal for this
                        # historical lane, but the caller's authenticated task
                        # runtime is still safe to use for the service marker.
                        # Retryable failures retain the fail-closed check path.
                        if (
                            task_id is None
                            or fallback_runtime is None
                            or fallback_runtime.task_id != loss.task_id
                            or isinstance(exc, PublicOperationError)
                            and exc.retryable
                        ):
                            raise
                        current = fallback_runtime
                        current_is_owned = False
                    store = self._observation_store(current)
                    observed_at = timestamp_from_datetime(self.clock.now_utc())
                    batch = materialize_selection_loss(loss, observed_at=observed_at)
                    operation_digest = _selection_loss_operation_digest(loss)
                    committed = await self._append_selection_loss_marker(
                        current,
                        loss,
                        batch,
                        operation_digest,
                    )
                    if committed is None:
                        raise ValueError("selection_loss_not_committed")
                    await store.record_selection_loss(workspace, loss, observed_at)
                    await self._run_advice(
                        workspace, current, store, session_commitment=loss.session_commitment
                    )
                    await self._local(
                        partial(self.local.acknowledge_selection_loss, workspace, loss.lane)
                    )
            except Exception as exc:
                if task_id is not None:
                    raise
                # Leave this lane pending and continue the other bounded lanes.
                # The sweeper deadline still interrupts an unavailable runtime.
                if not isinstance(exc, PublicOperationError) or not exc.retryable:
                    record_unexpected_exception_without_raising(
                        exc,
                        component="application.observation_coordinator",
                        operation="selection_loss_report_failed",
                    )
            finally:
                if current is not None and current_is_owned:
                    await self.runtime.release(current)

    async def _route_selection_loss(self, loss: ObservationSelectionLoss) -> TaskRuntime:
        # The loss already carries its authenticated historical route. Resolving
        # it must not depend on a still-live host mapping or recreate one after
        # SessionEnd pruning. Only a typed same-task successor can replace it.
        session = loss.session_id
        seen = {session}
        for _ in range(_MAX_SUPERSEDED_ROUTE_HOPS):
            try:
                opened = await self._route_observation_runtime(loss.task_id, session)
                if opened.task_id != loss.task_id or opened.session_id != session:
                    await self.runtime.release(opened)
                    raise ValueError("selection_loss_route_changed")
                return opened
            except PublicOperationError as error:
                successor = _session_superseded_binding(error, expected_task_id=loss.task_id)
                if successor is None or successor[0] in seen:
                    raise
                session = successor[0]
                seen.add(session)
        raise PublicOperationError(
            PublicErrorCode.SESSION_NOT_FOUND,
            "The observation loss route is unavailable.",
            retryable=False,
        )

    async def recover_capture_inventory(
        self, workspace: str
    ) -> ObservationCaptureRecoveryOutcome | tuple[ObservationCaptureRecoveryOutcome, ...] | None:
        """Repair capture accounting without requiring a newly admitted observation.

        The service sweep invokes this metadata-only path. Unknown inventory is
        repaired first. An aged native handoff is then reconciled against the
        structural rows that could still consume it, so one stranded ticket
        cannot hold oldest-age pressure at the hard limit while the outbox is
        empty (#836). Both steps return fixed outcomes and never admit input.
        """

        await self._reconcile_selection_losses(workspace)
        inventory_needed = await self._local(
            partial(self.local.capture_inventory_recovery_needed, workspace)
        )
        handoffs_due = bool(await self._capture_handoff_candidates(workspace))
        if not inventory_needed and not handoffs_due:
            return None
        if not self.observation_enabled or not await self._local(self.local.runtime_enabled):
            return ObservationCaptureRecoveryOutcome.DISABLED
        outcomes: list[ObservationCaptureRecoveryOutcome] = []
        if inventory_needed:
            inventory = await self._recover_capture_inventory_scope(workspace)
            if inventory is not None:
                if inventory is not ObservationCaptureRecoveryOutcome.RECOVERED:
                    # Handoffs are reconciled against a known inventory only;
                    # the next sweep retries both steps.
                    return inventory
                outcomes.append(inventory)
        handoff = await self._reconcile_capture_handoffs(workspace)
        if handoff is not None:
            outcomes.append(handoff)
        if not outcomes:
            return None
        return outcomes[0] if len(outcomes) == 1 else tuple(outcomes)

    async def _recover_capture_inventory_scope(
        self, workspace: str
    ) -> ObservationCaptureRecoveryOutcome | None:
        """Repair unknown inventory through an existing lifecycle mapping.

        It uses existing, unambiguous lifecycle mappings, not a synthetic
        envelope or a new grant. Eight mapping candidates per turn and a bounded
        rotating cursor keep missing parent/worker mappings from starving a
        usable route. The sweep owns the elapsed deadline; the authoritative
        bootstrap joins its local publication worker before cancellation can
        release the capture lock.
        """

        bootstrap = self.capture_budget_bootstrap
        if bootstrap is None:
            return ObservationCaptureRecoveryOutcome.INVENTORY_UNKNOWN
        if self._capture_lock.locked():
            return ObservationCaptureRecoveryOutcome.BUSY
        sessions = await self._local(
            partial(self.local.unambiguous_codex_sessions_for_workspace, workspace)
        )
        after = self._capture_recovery_sessions.get(workspace)
        if after is not None:
            sessions = tuple(item for item in sessions if item > after) + tuple(
                item for item in sessions if item <= after
            )
        outcome = ObservationCaptureRecoveryOutcome.MAPPING_MISSING
        for host_session in sessions[:8]:
            if (
                workspace not in self._capture_recovery_sessions
                and len(self._capture_recovery_sessions) >= _MAX_CAPTURE_BOOTSTRAP_WORKSPACES
            ):
                # Forgetting an old hint never publishes an inventory proof.
                self._capture_recovery_sessions.pop(next(iter(self._capture_recovery_sessions)))
            self._capture_recovery_sessions[workspace] = host_session
            current_runtime: TaskRuntime | None = None
            try:
                mapping = await self._local(
                    partial(self.mapping_loader, host_session, _state=self.state_root)
                )
                if mapping is None:
                    continue
                current_runtime, _ = await self._route_observation_mapping(
                    mapping, required_capabilities=frozenset({RuntimeCapability.WRITE})
                )
                store = self._observation_store(current_runtime)
                # Do not queue behind another capture or hold the general
                # workflow gate across a catalog/bundle inventory scan.
                if self._capture_lock.locked():
                    return ObservationCaptureRecoveryOutcome.BUSY
                async with self._capture_lock:
                    if not await self._local(
                        partial(self.local.capture_inventory_recovery_needed, workspace)
                    ):
                        return None
                    if await bootstrap(workspace, current_runtime, store):
                        self._remember_capture_bootstrap(workspace)
                        return ObservationCaptureRecoveryOutcome.RECOVERED
                    self._capture_bootstrap_verified_workspaces.discard(workspace)
                    # One complete-inventory attempt per workspace turn. A
                    # sibling mapping cannot repair the same unreadable catalog.
                    return ObservationCaptureRecoveryOutcome.INVENTORY_UNKNOWN
            except Exception:
                self._capture_bootstrap_verified_workspaces.discard(workspace)
                outcome = ObservationCaptureRecoveryOutcome.ROUTE_UNAVAILABLE
            finally:
                if current_runtime is not None:
                    await self.runtime.release(current_runtime)
        return outcome

    async def _reserve_capture_ticket(
        self,
        workspace: str,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        ticket: ObservationCaptureTicket,
        byte_count: int,
    ) -> None:
        """Reserve global count/bytes before any encrypted object is staged."""

        ready = getattr(self.local, "capture_reservation_bootstrap_ready", None)
        if callable(ready):
            try:
                locally_ready = await self._local(partial(ready, workspace, runtime.task_id))
                if (
                    not locally_ready
                    or workspace not in self._capture_bootstrap_verified_workspaces
                ):
                    if self.capture_budget_bootstrap is None or not (
                        await self.capture_budget_bootstrap(workspace, runtime, store)
                    ):
                        mark_unknown = getattr(
                            self.local, "mark_capture_backlog_scope_unknown", None
                        )
                        if callable(mark_unknown):
                            await self._local(partial(mark_unknown, workspace))
                        raise PublicOperationError(
                            PublicErrorCode.LIMIT_EXCEEDED,
                            "Observation capture budget scope is unknown.",
                            retryable=False,
                        )
                    self._remember_capture_bootstrap(workspace)
            except PublicOperationError:
                self._capture_bootstrap_verified_workspaces.discard(workspace)
                raise
            except Exception as exc:
                self._capture_bootstrap_verified_workspaces.discard(workspace)
                mark_unknown = getattr(self.local, "mark_capture_backlog_scope_unknown", None)
                if callable(mark_unknown):
                    await self._local(partial(mark_unknown, workspace))
                raise PublicOperationError(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "Observation capture budget scope is unknown.",
                    retryable=False,
                ) from exc
        reserve = getattr(self.local, "reserve_capture_ticket", None)
        if not callable(reserve):
            return
        await self._local(
            partial(
                reserve,
                workspace,
                observation_capture_ticket_id(ticket),
                runtime.task_id,
                byte_count,
            )
        )

    @staticmethod
    def _capture_part_identity(
        chunk: ObservationContentChunk | ObservationContentManifest,
    ) -> tuple[str, str | None, str | None, int]:
        """Return the durable identity used to deduplicate one capture part."""

        return (
            chunk.content_kind.value,
            chunk.correlation_identity,
            chunk.source_commitment,
            chunk.part_index,
        )

    @classmethod
    def _capture_ticket_reservation_bytes(
        cls,
        store: TaskObservationPort,
        *,
        workspace: str,
        ticket: ObservationCaptureTicket,
        chunks: tuple[ObservationContentChunk, ...],
    ) -> int:
        """Compute a conservative ticket byte upper bound before object staging.

        A retry may contain a mixture of already durable parts and new parts.
        Charge the retained manifest bytes once, then add only request parts
        whose trusted part identity is not already present. Historical rows
        without byte metadata are treated as occupying the complete budget so
        that missing accounting can never open a path around the central fence.
        """

        requested_by_part = {
            cls._capture_part_identity(chunk): len(chunk.content) for chunk in chunks
        }
        manifests = store.content_manifests_for_logical_identity(
            workspace=workspace,
            logical_identity=ticket.logical_identity,
        )
        retained_by_part: dict[tuple[str, str | None, str | None, int], int | None] = {}
        retained_object_ids: set[str] = set()
        for manifest in manifests:
            part = cls._capture_part_identity(manifest)
            retained_object_ids.add(manifest.object_id)
            if part in retained_by_part:
                if retained_by_part[part] != manifest.content_bytes:
                    raise PublicOperationError(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Observation content manifest conflicts.",
                        retryable=False,
                    )
                continue
            retained_by_part[part] = manifest.content_bytes

        retained_bytes = 0
        for part, content_bytes in retained_by_part.items():
            if content_bytes is None:
                # A current retry can supply a safe upper bound for this
                # legacy row. Without that part in the request, no bounded
                # estimate exists, so force the reservation to the fence.
                content_bytes = requested_by_part.get(part, _MAX_CAPTURE_CONTENT_BYTES)
            retained_bytes += content_bytes

        # A pending ticket's object list is authenticated ticket metadata. If
        # a manifest has disappeared from the lookup, keep its occupancy
        # conservative instead of allowing a retry to replace it uncharged.
        if any(object_id not in retained_object_ids for object_id in ticket.object_ids):
            retained_bytes = _MAX_CAPTURE_CONTENT_BYTES

        requested_new_bytes = sum(
            byte_count
            for part, byte_count in requested_by_part.items()
            if part not in retained_by_part
        )
        total = retained_bytes + requested_new_bytes
        if total > _MAX_CAPTURE_CONTENT_BYTES:
            raise PublicOperationError(
                PublicErrorCode.LIMIT_EXCEEDED,
                "Observation captured-content byte budget is exhausted.",
                retryable=False,
            )
        return total

    async def _confirm_capture_ticket_reservation(
        self,
        workspace: str,
        runtime: TaskRuntime,
        ticket: ObservationCaptureTicket,
    ) -> None:
        """Clear the crash-reconciliation fence after the ticket row is durable."""

        confirm = getattr(self.local, "confirm_capture_ticket_reservation", None)
        if not callable(confirm):
            return
        try:
            await self._local(
                partial(
                    confirm,
                    workspace,
                    observation_capture_ticket_id(ticket),
                    runtime.task_id,
                )
            )
        except Exception:
            # A reservation that remains marked for reconciliation is safe:
            # pressure stays conservative until READY can inspect the ticket.
            return

    async def _release_capture_ticket_reservation(
        self,
        workspace: str,
        runtime: TaskRuntime,
        ticket: ObservationCaptureTicket,
    ) -> None:
        """Release global capacity only after durable ticket retirement."""

        release = getattr(self.local, "release_capture_ticket_reservation", None)
        if not callable(release):
            return
        try:
            await self._local(
                partial(
                    release,
                    workspace,
                    observation_capture_ticket_id(ticket),
                    runtime.task_id,
                )
            )
        except Exception:
            # The reservation remains conservative and is removed by the next
            # successful READY reconciliation.
            return

    async def _reconcile_capture_ticket_reservations(
        self,
        workspace: str,
        runtime: TaskRuntime,
        store: TaskObservationPort,
    ) -> None:
        """Reconcile central reservations against one task's durable ticket rows."""

        reconcile = getattr(self.local, "reconcile_capture_ticket_reservations", None)
        list_pending = getattr(store, "list_pending_capture_tickets", None)
        if not callable(reconcile) or not callable(list_pending):
            return
        try:
            rows = cast(tuple[object, ...], list_pending(runtime.task_id))
            if type(rows) is not tuple:
                return
            ticket_ids_list: list[str] = []
            for row in rows:
                if type(row) is not ObservationCaptureTicket:
                    return
                ticket_ids_list.append(observation_capture_ticket_id(row))
            ticket_ids = tuple(ticket_ids_list)
            await self._local(
                partial(
                    reconcile,
                    workspace,
                    runtime.task_id,
                    ticket_ids,
                )
            )
        except Exception:
            # Preserve ``needs_reconcile`` or unknown scope on any read error;
            # this path never weakens capture admission.
            return

    async def _capture_handoff_candidates(self, workspace: str) -> tuple[str, ...]:
        """Read the task routes that own aged handoffs; an older store reports none."""

        candidates = getattr(self.local, "capture_handoff_candidates", None)
        if not callable(candidates):
            return ()
        try:
            raw = await self._local(partial(candidates, workspace))
        except Exception:
            return ()
        values = cast(tuple[object, ...], raw)
        if type(raw) is not tuple or any(type(item) is not str for item in values):
            return ()
        return cast(tuple[str, ...], raw)

    def _select_capture_handoff_candidates(
        self, workspace: str, candidates: tuple[str, ...]
    ) -> tuple[str, ...]:
        """Rotate bounded maintenance work past the last attempted task route."""

        if not candidates:
            self._capture_handoff_after.pop(workspace, None)
            return ()
        after = self._capture_handoff_after.get(workspace)
        start = 0
        if after is not None:
            try:
                start = (candidates.index(after) + 1) % len(candidates)
            except ValueError:
                # A retired route disappearing is progress; restart from the
                # current authority-ordered list without inventing a route.
                start = 0
        ordered = candidates[start:] + candidates[:start]
        selected = ordered[:_MAX_CAPTURE_HANDOFF_TASKS_PER_TURN]
        if workspace not in self._capture_handoff_after and len(self._capture_handoff_after) >= 256:
            self._capture_handoff_after.pop(next(iter(self._capture_handoff_after)))
        self._capture_handoff_after[workspace] = selected[-1]
        return selected

    def _capture_handoff_age_ms(self, ticket: ObservationCaptureTicket) -> int:
        """Age a durable ticket against the service clock; unknown clocks read as fresh."""

        try:
            now = timestamp_from_datetime(self.clock.now_utc())
        except Exception:
            return 0
        if ticket.captured_at >= now:
            return 0
        delta = now.as_datetime() - ticket.captured_at.as_datetime()
        return delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000

    async def _record_capture_handoff_retirement(
        self,
        workspace: str,
        ticket: ObservationCaptureTicket,
        *,
        stage: CaptureHandoffRetirementStage,
        reason: CaptureHandoffRetirementReason,
        quarantine_reason: str | None = None,
    ) -> bool:
        """Durably account for one retirement before its ticket is destroyed.

        The local account is keyed by the immutable ticket identity, so a
        cancellation or crash after this write but before ticket retirement
        can safely replay the accounting without duplicating the loss marker.
        A failed account leaves the ticket active for a later retry.
        """

        recorder = getattr(self.local, "record_capture_handoff_retirement", None)
        if not callable(recorder) or ticket.state not in {"staging", "pending"}:
            return False
        try:
            await self._local(
                partial(
                    recorder,
                    workspace,
                    ticket_id=observation_capture_ticket_id(ticket),
                    stage=stage,
                    reason=reason,
                    ticket_state=ticket.state,
                    source=ticket.source,
                    task_id=ticket.task_id,
                    age_ms=self._capture_handoff_age_ms(ticket),
                    quarantine_reason=quarantine_reason,
                )
            )
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="application.observation_coordinator",
                operation="capture_handoff_retirement_record_failed",
            )
            return False
        return True

    async def _publish_capture_handoff_retirement(
        self,
        runtime: TaskRuntime,
        ticket: ObservationCaptureTicket,
        reason: CaptureHandoffRetirementReason,
    ) -> bool:
        """Put one retiring handoff on its own task's coverage (issue #1019, tb4n2 N-4).

        Called after the local loss account and *before* the ticket is tombstoned: the ledger
        marker is the durable disclosure, so it must exist before the ticket stops being listed
        for reconciliation. Only the ticket's own task receives it, keyed by the ticket identity,
        so a retry after an interrupted retirement appends nothing new. Returns ``False`` when the
        marker is not durable yet but could become so (a retryable or unexpected failure); the
        caller then leaves the ticket pending, and the next reconciliation pass (the READY sweep or
        a CHECK preflight) publishes it again. A ledger that terminally refuses the marker (a
        non-retryable typed refusal, an operation conflict, or no writer) can never hold it, so
        the retirement proceeds rather than holding capture pressure forever; that refusal is
        recorded in service diagnostics.
        """

        if ticket.task_id != runtime.task_id:
            return False
        try:
            ticket_id = observation_capture_ticket_id(ticket)
            batch = materialize_capture_handoff_retirement(
                task_id=runtime.task_id,
                ticket_id=ticket_id,
                reason=reason.value,
                observed_at=timestamp_from_datetime(self.clock.now_utc()),
            )
            digest = canonical_digest(
                JsonObject(
                    {
                        "format": "yoetz.capture-handoff-retirement-report/1",
                        "task_id": runtime.task_id,
                        "ticket_id": ticket_id,
                    }
                )
            )
            if runtime.writer_id is None:
                return True
            await self._append_structural_batch(runtime, batch, digest)
            return True
        except Exception as exc:
            terminal = (isinstance(exc, PublicOperationError) and not exc.retryable) or isinstance(
                exc, ProtocolValueError | ValueError
            )
            if not isinstance(exc, PublicOperationError) or not exc.retryable:
                record_unexpected_exception_without_raising(
                    exc,
                    component="application.observation_coordinator",
                    operation="capture_handoff_retirement_publish_failed",
                )
            return terminal

    async def _retire_stranded_capture_handoff(
        self,
        workspace: str,
        runtime: TaskRuntime | None,
        store: TaskObservationPort | None,
        handoff: _StructuralCaptureHandoff,
        *,
        stage: CaptureHandoffRetirementStage,
        reason: CaptureHandoffRetirementReason,
    ) -> None:
        """Retire a handoff its own structural row can no longer consume.

        Called after that row committed or was refused terminally. The capture
        lock serializes this with capture-only staging, so a handoff staged
        while the row was being delivered is retired here, and a later request
        finds the row already accepted and stages nothing. The durable ticket is
        re-read and must match this exact native row, so a consumed ticket or
        another row's handoff is never touched. Cleanup never changes the
        delivery's outcome: a failure is recorded and the READY sweep retires
        the handoff later.
        """

        envelope = handoff.envelope
        identity = handoff.content_identity
        loader = getattr(store, "load_capture_ticket", None)
        if envelope is None or identity is None or runtime is None or not callable(loader):
            return
        assert store is not None
        try:
            async with self._capture_lock:
                ticket = loader(workspace=workspace, logical_identity=identity)
                if (
                    type(ticket) is not ObservationCaptureTicket
                    or ticket.state not in {"staging", "pending"}
                    or ticket.task_id != runtime.task_id
                    or ticket.session_commitment != envelope.session_commitment
                    or ticket.source is not envelope.source
                    or ticket.source_identity != envelope.source_identity
                    or ticket.cursor != envelope.cursor
                ):
                    return
                if not await self._record_capture_handoff_retirement(
                    workspace, ticket, stage=stage, reason=reason
                ):
                    return
                if not await self._publish_capture_handoff_retirement(runtime, ticket, reason):
                    # The disclosure is not durable yet: keep the ticket listed so a later
                    # reconciliation pass retires it and publishes the marker.
                    return
                await self._retire_capture_ticket(workspace, runtime, store, ticket)
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="application.observation_coordinator",
                operation="capture_handoff_stranded_retirement_failed",
            )

    async def _reconcile_task_capture_handoffs(
        self,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        *,
        stage: CaptureHandoffRetirementStage,
        workspace: str | None = None,
        structural: bool = True,
    ) -> int:
        """Retire this task's handoffs that no current authority or live row backs.

        With ``structural`` the caller holds the capture lock, so no capture-only
        request can stage a handoff during this pass. The structural rows are
        read before the tickets that are classified: a ticket still listed
        afterwards whose row was already gone cannot be consumed any more,
        because a delivery deletes its ticket before the drain acknowledges or
        quarantines the row. ``workspace`` limits the pass to one workspace and
        republishes that workspace's backlog even when no ticket remains, which
        releases a reservation that outlived its ticket.
        """

        list_pending = getattr(store, "list_pending_capture_tickets", None)
        if not callable(list_pending) or not callable(
            getattr(store, "tombstone_capture_ticket", None)
        ):
            return 0

        schema_probe = getattr(store, "capture_ticket_schema_available", None)
        schema_available = False
        if callable(schema_probe):
            try:
                schema_available = await self._local(schema_probe) is True
            except Exception:
                return 0
            if not schema_available:
                # An older bundle cannot provide a complete active-ticket
                # authority. Preserve pending accounting and leave the ticket
                # lane for a later migration-aware pass.
                return 0

        def listing() -> tuple[tuple[ObservationCaptureTicket, ...], bool]:
            raw: object = list_pending(runtime.task_id)
            values = cast(tuple[object, ...], raw)
            if type(raw) is not tuple or any(
                type(item) is not ObservationCaptureTicket or item.task_id != runtime.task_id
                for item in values
            ):
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Observation capture ticket listing is invalid.",
                    retryable=False,
                )
            typed_raw = cast(tuple[ObservationCaptureTicket, ...], raw)
            complete = len(typed_raw) < _MAX_CAPTURE_TICKETS_PER_TASK
            filtered = tuple(
                item
                for item in typed_raw
                if workspace is None or item.workspace_commitment == workspace
            )
            return filtered, complete

        initial_tickets, _initial_listing_complete = listing()
        workspaces = {item.workspace_commitment for item in initial_tickets}
        if workspace is not None:
            workspaces.add(workspace)
        elif callable(getattr(self.local, "capture_handoff_retirement_workspaces", None)):
            pending_workspaces = await self._local(
                partial(
                    self.local.capture_handoff_retirement_workspaces,
                    runtime.task_id,
                )
            )
            pending_values = cast(tuple[object, ...], pending_workspaces)
            if type(pending_workspaces) is not tuple or any(
                type(item) is not str for item in pending_values
            ):
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Observation capture retirement workspace listing is invalid.",
                    retryable=False,
                )
            workspaces.update(pending_workspaces)
        structural_states: dict[str, CaptureHandoffStructuralState | None] = {}
        reader = getattr(self.local, "capture_handoff_structural_state", None)
        for current_workspace in sorted(workspaces, key=str.encode):
            state: CaptureHandoffStructuralState | None = None
            if structural and callable(reader):
                state = cast(
                    CaptureHandoffStructuralState,
                    await self._local(partial(reader, current_workspace)),
                )
            structural_states[current_workspace] = state
        tickets, listing_complete = listing()
        reconciler = getattr(self.local, "reconcile_capture_handoff_retirements", None)
        if callable(reconciler) and schema_available and listing_complete:
            for current_workspace in sorted(structural_states, key=str.encode):
                active_ticket_ids = tuple(
                    observation_capture_ticket_id(item)
                    for item in tickets
                    if item.workspace_commitment == current_workspace
                )
                await self._local(
                    partial(
                        reconciler,
                        current_workspace,
                        runtime.task_id,
                        active_ticket_ids,
                    )
                )
        authorities: dict[str, LocalContentCaptureAuthority | None] = {}
        retired = 0
        for ticket in tickets:
            current_workspace = ticket.workspace_commitment
            if current_workspace not in structural_states:
                # Staged after the structural read: never classified this pass.
                continue
            if current_workspace not in authorities:
                authorities[current_workspace] = await self._local(
                    partial(self.local.content_capture_authority, current_workspace)
                )
            decision = _capture_handoff_retirement_reason(
                ticket,
                authorities[current_workspace],
                structural_states[current_workspace],
                age_ms=self._capture_handoff_age_ms(ticket),
            )
            if decision is None:
                continue
            reason, quarantine_reason = decision
            if not await self._record_capture_handoff_retirement(
                current_workspace,
                ticket,
                stage=stage,
                reason=reason,
                quarantine_reason=quarantine_reason,
            ):
                continue
            if not await self._publish_capture_handoff_retirement(runtime, ticket, reason):
                # Not durable yet: the ticket stays listed and the next pass retries.
                continue
            await self._retire_capture_ticket(current_workspace, runtime, store, ticket)
            retired += 1
        for current_workspace in sorted(structural_states, key=str.encode):
            await self._publish_capture_backlog(current_workspace, runtime, store)
        return retired

    async def reconcile_task_capture_handoffs(self, runtime: TaskRuntime) -> int:
        """Retire a routed task's stranded handoffs before a CHECK retries its freeze.

        A CHECK never waits behind capture work: while the capture lock is busy
        only the authority rules run, and the READY sweep reconciles aged
        handoffs against their structural rows later (#836).
        """

        store = runtime.observation
        if store is None:
            return 0
        if self._capture_lock.locked():
            return await self._reconcile_task_capture_handoffs(
                runtime,
                store,
                stage=CaptureHandoffRetirementStage.CHECK_PREFLIGHT,
                structural=False,
            )
        async with self._capture_lock:
            return await self._reconcile_task_capture_handoffs(
                runtime, store, stage=CaptureHandoffRetirementStage.CHECK_PREFLIGHT
            )

    async def _reconcile_capture_handoffs(
        self, workspace: str
    ) -> ObservationCaptureRecoveryOutcome | None:
        """Visit the tasks that own aged handoffs, oldest first, under the capture lock.

        A handoff kept by current authority and a still-pending structural row
        remains, so a genuinely pending capture keeps its oldest-age pressure;
        that turn reports no outcome.
        """

        candidates = await self._capture_handoff_candidates(workspace)
        if not candidates:
            return None
        if self._capture_lock.locked():
            return ObservationCaptureRecoveryOutcome.BUSY
        task_ids = self._select_capture_handoff_candidates(workspace, candidates)
        retired = 0

        async def visit(task_runtime: TaskRuntime, task_store: TaskObservationPort) -> int:
            nonlocal retired
            count = await self._reconcile_task_capture_handoffs(
                task_runtime,
                task_store,
                stage=CaptureHandoffRetirementStage.SWEEP,
                workspace=workspace,
            )
            retired += count
            return count

        async with self._capture_lock:
            hook = self.capture_handoff_reconcile
            if hook is not None:
                try:
                    complete = await hook(workspace, task_ids, visit)
                except Exception:
                    complete = False
            else:
                complete = await self._reconcile_mapped_capture_handoffs(workspace, task_ids, visit)
        if retired:
            return ObservationCaptureRecoveryOutcome.HANDOFF_RETIRED
        if not complete:
            return ObservationCaptureRecoveryOutcome.HANDOFF_UNAVAILABLE
        return None

    async def _reconcile_mapped_capture_handoffs(
        self,
        workspace: str,
        task_ids: tuple[str, ...],
        visit: CaptureHandoffVisitor,
    ) -> bool:
        """Reach handoff tasks through existing mappings when READY supplies no router."""

        remaining = set(task_ids)
        sessions = await self._local(
            partial(self.local.unambiguous_codex_sessions_for_workspace, workspace)
        )
        for host_session in sessions[:_MAX_CAPTURE_HANDOFF_TASKS_PER_TURN]:
            if not remaining:
                break
            current_runtime: TaskRuntime | None = None
            try:
                mapping = await self._local(
                    partial(self.mapping_loader, host_session, _state=self.state_root)
                )
                if mapping is None or mapping.yoetz_task_id not in remaining:
                    continue
                current_runtime, _ = await self._route_observation_mapping(
                    mapping, required_capabilities=frozenset({RuntimeCapability.WRITE})
                )
                await visit(current_runtime, self._observation_store(current_runtime))
                remaining.discard(current_runtime.task_id)
            except Exception:
                continue
            finally:
                if current_runtime is not None:
                    await self.runtime.release(current_runtime)
        return not remaining

    def _release_finished(self, pending: asyncio.Future[None]) -> None:
        self._pending_releases.discard(pending)
        if pending.cancelled():
            return
        error = pending.exception()
        if isinstance(error, Exception):
            record_unexpected_exception_without_raising(
                error,
                component="application.observation_coordinator",
                operation="observation_runtime_release_failed",
            )

    def close(self) -> None:
        """Stop accepting local-store work; bounded lock waits let running workers retire."""

        executor, self._local_executor = self._local_executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()
        self._capture_lock = asyncio.Lock()
        if type(self.observation_enabled) is not bool:
            raise TypeError("observation_enabled_invalid")
        if self.verification_supervisor is None:
            # Tests and non-ready compositions still drain inline when no supervisor
            # is attached; production ready composition always injects one.
            self.verification_supervisor = None

    async def rediscover_pending_verification(self) -> None:
        """Rebuild drain handles for consented workspaces with durable pending jobs.

        Called once after ready-lifecycle supervisor start so restart reclaim can
        complete without waiting for a fresh hook ingest.
        """

        supervisor = self.verification_supervisor
        if supervisor is None:
            return
        for workspace in await self._local(self.local.list_consented_workspaces):
            await self._rediscover_workspace_pending_verification(supervisor, workspace)
        supervisor.notify()

    async def _rediscover_workspace_pending_verification(
        self,
        supervisor: ObservationVerificationSupervisor,
        workspace: str,
        *,
        sessions: tuple[str, ...] | None = None,
        start_index: int = 0,
        task_id: str | None = None,
    ) -> None:
        """Register pending session repositories for one workspace and task lane.

        Initial discovery may find sibling tasks that share one source workspace. Each registered
        handle therefore uses the routed task as its supervisor key, while an idle callback keeps
        scanning only the remaining source sessions.
        """

        if supervisor.closed:
            return
        consent = await self._local(partial(self.local.consent_for, workspace))
        if consent is None or not consent.active:
            return
        if sessions is None:
            sessions = await self._local(
                partial(self.local.codex_sessions_for_workspace, workspace)
            )
        for session_index, codex_session_id in enumerate(sessions[start_index:], start=start_index):
            if supervisor.closed:
                return
            mapping = self.mapping_loader(codex_session_id, _state=self.state_root)
            if mapping is None:
                continue
            if task_id is not None and mapping.yoetz_task_id != task_id:
                continue
            predecessor_session_id = mapping.yoetz_session_id
            predecessor_writer_id = mapping.yoetz_writer_id
            runtime: TaskRuntime | None = None
            try:
                runtime, mapping = await self._route_observation_mapping(mapping)
                # The repository is task-bundle local. A sibling task may use the same source
                # workspace, so suppress only a duplicate handle for this task lane.
                if supervisor.has_handle(workspace, runtime.task_id):
                    continue
                store = self._observation_store(runtime)
                repository = getattr(store, "verification_repository", None)
                if not callable(repository):
                    continue
                repo = cast(ObservationVerificationRepository, repository())
                pending = repo.list_pending_workspaces()
                if workspace not in pending:
                    continue
                worker = await self._rebuild_verification_worker(
                    runtime,
                    workspace,
                    store,
                    legacy_session_id=predecessor_session_id,
                    legacy_writer_id=predecessor_writer_id,
                )
                if worker is None:
                    continue

                async def _after(
                    bound_workspace: str = workspace,
                    bound_runtime: TaskRuntime = runtime,
                    bound_store: TaskObservationPort = store,
                    bound_legacy_writer_id: str = predecessor_writer_id,
                ) -> None:
                    await self._run_advice(
                        bound_workspace,
                        bound_runtime,
                        bound_store,
                        legacy_writer_id=bound_legacy_writer_id,
                    )

                async def _release_and_continue(
                    bound_runtime: TaskRuntime = runtime,
                    bound_workspace: str = workspace,
                    bound_sessions: tuple[str, ...] = sessions,
                    next_session_index: int = session_index + 1,
                ) -> None:
                    await self.runtime.release(bound_runtime)
                    await self._rediscover_workspace_pending_verification(
                        supervisor,
                        bound_workspace,
                        sessions=bound_sessions,
                        start_index=next_session_index,
                        task_id=bound_runtime.task_id,
                    )

                async def _failed(
                    bound_workspace: str = workspace,
                    bound_session_id: str = codex_session_id,
                ) -> None:
                    session_commitment = await self._local(
                        partial(self.local.session_commitment, bound_session_id)
                    )
                    await self._local(
                        partial(
                            self.local.note_session_coverage_gap,
                            bound_workspace,
                            session_commitment,
                            ObservationGapCode.VERIFICATION_STALE.value,
                        )
                    )

                registered = supervisor.register(
                    VerificationDrainHandle(
                        workspace_commitment=workspace,
                        worker=worker,
                        after_complete=_after,
                        on_idle=_release_and_continue,
                        task_id=runtime.task_id,
                        on_failure=_failed,
                    )
                )
                if registered:
                    runtime = None
                # Continue so sibling task lanes can be registered. A same-task second session is
                # suppressed by the lane key above.
                continue
            except Exception:
                session_commitment = await self._local(
                    partial(self.local.session_commitment, codex_session_id)
                )
                await self._local(
                    partial(
                        self.local.note_session_coverage_gap,
                        workspace,
                        session_commitment,
                        ObservationGapCode.VERIFICATION_STALE.value,
                    )
                )
            finally:
                if runtime is not None:
                    release = getattr(self.runtime, "release", None)
                    if release is not None:
                        await release(runtime)

    async def _native_capture_context(
        self,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        *,
        workspace: str,
        request: ObservationIngestRequest,
        consent: Any,
        admitted_ticket_session_ids: frozenset[str] | None = None,
    ) -> _NativeCaptureContext:
        """Resolve the native capture fence and durable handoff before object capture."""

        if admitted_ticket_session_ids is None:
            admitted_ticket_session_ids = frozenset({runtime.session_id})
        profiled_native_source = request.envelope.source in {
            ObservationSource.CLAUDE_HOOK,
            ObservationSource.CURSOR_HOOK,
        }
        profileless_codex_source = request.envelope.source is ObservationSource.CODEX_HOOK
        # A Codex structural request with inline chunks retains the historical
        # capture path. It enters the ticketed lane only when the hook has
        # explicitly requested capture-only staging or a prior handoff is
        # being recovered below.
        native_source = profiled_native_source
        requested_profile = request.content_capture_profile
        content_identity = (
            observation_content_identity(request.envelope)
            if profiled_native_source or profileless_codex_source
            else None
        )
        pending_ticket: ObservationCaptureTicket | None = None
        ticket_revoked = False
        rejection_reason: str | None = None
        requested_capture_parts = observation_capture_part_descriptors(request.content_chunks)
        ticket_schema_available = True
        ticket_schema_probe = getattr(store, "capture_ticket_schema_available", None)
        if callable(ticket_schema_probe):
            ticket_schema_available = bool(ticket_schema_probe())
        if content_identity is not None:
            if ticket_schema_available:
                pending_ticket = store.load_capture_ticket(
                    workspace=workspace,
                    logical_identity=content_identity,
                )
            if pending_ticket is not None:
                if (
                    pending_ticket.session_commitment != request.envelope.session_commitment
                    or pending_ticket.yoetz_session_id not in admitted_ticket_session_ids
                    or pending_ticket.task_id != runtime.task_id
                    or pending_ticket.source is not request.envelope.source
                    or pending_ticket.source_identity != request.envelope.source_identity
                    or pending_ticket.cursor != request.envelope.cursor
                ):
                    rejection_reason = ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
                elif requested_profile is None:
                    requested_profile = pending_ticket.content_capture_profile
                ticket_revoked = pending_ticket.state == "revoked"
        if profileless_codex_source and (
            request.capture_only
            or pending_ticket is not None
            or bool(request.envelope.content_object_refs)
        ):
            native_source = True
        expected_capture_parts: tuple[ObservationCapturePart, ...] | None = None
        if ticket_schema_available and (pending_ticket is not None or request.content_chunks):
            expected_capture_parts = requested_capture_parts
            if pending_ticket is not None:
                if not set(requested_capture_parts).issubset(pending_ticket.expected_parts):
                    rejection_reason = ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
                expected_capture_parts = pending_ticket.expected_parts
        profile_source_mismatch = (
            rejection_reason is None
            and requested_profile is not None
            and (
                not profiled_native_source
                or not content_capture_profile_matches_source(
                    request.envelope.source.value, requested_profile
                )
            )
        )
        profile_consent_missing = (
            rejection_reason is None
            and not profile_source_mismatch
            and requested_profile is not None
            and requested_profile not in consent.content_capture_profiles
        )
        if profile_source_mismatch or profile_consent_missing:
            # A profile that was explicitly disabled/revoked fences the
            # matching durable handoff. A source/profile metadata mismatch is
            # left for the ticket metadata owner to diagnose instead of being
            # silently mutated here.
            if profile_consent_missing and pending_ticket is not None:
                self._tombstone_capture_tickets(
                    store,
                    workspace,
                    pending_ticket.content_capture_profile,
                )
                await self._release_capture_ticket_reservation(workspace, runtime, pending_ticket)
            rejection_reason = ObservationGapCode.CONTENT_CAPTURE_PROFILE_MISMATCH.value

        content_authorized = not native_source
        content_authorization_missing = False
        content_blocked = ticket_revoked
        capture_fence: Callable[[], Awaitable[bool]] | None = None
        native_requested = native_source and bool(
            request.content_chunks
            or request.envelope.content_object_refs
            or pending_ticket is not None
        )
        fence_generation: str | None = None
        fence_profiles: tuple[str, ...] = ()
        if native_requested:
            authority = await self._local(partial(self.local.content_capture_authority, workspace))
            if (
                authority is None
                or not authority.active
                or not authority.runtime_enabled
                or (profiled_native_source and not authority.profiles)
            ):
                content_blocked = True
            else:
                fence_generation = authority.generation
                fence_profiles = authority.profiles
                if (
                    pending_ticket is not None
                    and pending_ticket.authority_generation != fence_generation
                ):
                    await self._retire_capture_ticket(workspace, runtime, store, pending_ticket)
                    ticket_revoked = True
                    content_blocked = True

                async def current_capture_fence() -> bool:
                    assert fence_generation is not None
                    return await self._local(
                        partial(
                            self.local.content_capture_authority_is_current,
                            workspace,
                            fence_generation,
                            fence_profiles,
                        )
                    )

                capture_fence = current_capture_fence
        if native_source and (request.content_chunks or pending_ticket is not None):
            stored_profiles = store.content_capture_profiles(workspace)
            if profileless_codex_source:
                # Codex hook content uses the existing structural observation
                # grant as its authority arm. There is intentionally no Codex
                # profile in the public profile vocabulary.
                content_authorized = requested_profile is None
            else:
                content_authorized = (
                    requested_profile is not None
                    and requested_profile in stored_profiles
                    and requested_profile in fence_profiles
                    and content_capture_profile_matches_source(
                        request.envelope.source.value, requested_profile
                    )
                )
            content_authorization_missing = not content_authorized
        if native_requested and not content_blocked:
            assert capture_fence is not None
            if not await capture_fence():
                content_blocked = True
                content_authorized = False
                content_authorization_missing = True

        staging_ticket: ObservationCaptureTicket | None = None
        staged_ticket: ObservationCaptureTicket | None = None
        if (
            native_requested
            and not content_blocked
            and content_authorized
            and content_identity is not None
            and fence_generation is not None
        ):
            if pending_ticket is not None:
                if pending_ticket.state == "staging":
                    staging_ticket = pending_ticket
                    await self._reserve_capture_ticket(
                        workspace,
                        runtime,
                        store,
                        pending_ticket,
                        self._capture_ticket_reservation_bytes(
                            store,
                            workspace=workspace,
                            ticket=pending_ticket,
                            chunks=request.content_chunks,
                        ),
                    )
                    await self._confirm_capture_ticket_reservation(
                        workspace, runtime, pending_ticket
                    )
                elif pending_ticket.state == "pending":
                    staged_ticket = pending_ticket
                    await self._reserve_capture_ticket(
                        workspace,
                        runtime,
                        store,
                        pending_ticket,
                        self._capture_ticket_reservation_bytes(
                            store,
                            workspace=workspace,
                            ticket=pending_ticket,
                            chunks=request.content_chunks,
                        ),
                    )
                    await self._confirm_capture_ticket_reservation(
                        workspace, runtime, pending_ticket
                    )
            elif (
                request.content_chunks
                and ticket_schema_available
                and request.capture_only
                and await self._structural_row_passed(store, workspace, request.envelope)
            ):
                # A capture-only request that arrives after its structural row
                # was accepted and acknowledged (a lease-free drain delivered it
                # first) must not stage a handoff: only that row can consume a
                # ticket, and the FIFO has moved past it (#836).
                rejection_reason = ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
                await self._local(
                    partial(self.local.note_coverage_gap, workspace, rejection_reason)
                )
            elif request.content_chunks and ticket_schema_available:
                staging_ticket = ObservationCaptureTicket(
                    workspace_commitment=workspace,
                    task_id=runtime.task_id,
                    yoetz_session_id=runtime.session_id,
                    session_commitment=request.envelope.session_commitment,
                    source=request.envelope.source,
                    source_identity=request.envelope.source_identity,
                    cursor=request.envelope.cursor,
                    logical_identity=content_identity,
                    content_capture_profile=requested_profile,
                    authority_generation=fence_generation,
                    object_ids=(),
                    captured_at=timestamp_from_datetime(self.clock.now_utc()),
                    state="staging",
                    expected_parts=expected_capture_parts or (),
                )
                try:
                    await self._reserve_capture_ticket(
                        workspace,
                        runtime,
                        store,
                        staging_ticket,
                        self._capture_ticket_reservation_bytes(
                            store,
                            workspace=workspace,
                            ticket=staging_ticket,
                            chunks=request.content_chunks,
                        ),
                    )
                    store.record_capture_ticket(staging_ticket)
                except Exception:
                    await self._release_capture_ticket_reservation(
                        workspace, runtime, staging_ticket
                    )
                    raise
                await self._confirm_capture_ticket_reservation(workspace, runtime, staging_ticket)
        return _NativeCaptureContext(
            native_source=native_source,
            requested_content_profile=requested_profile,
            content_identity=content_identity,
            pending_capture_ticket=pending_ticket,
            content_authorized=content_authorized,
            content_authorization_missing=content_authorization_missing,
            content_capture_blocked=content_blocked,
            capture_ticket_revoked=ticket_revoked,
            native_content_requested=native_requested,
            capture_fence=capture_fence,
            fence_generation=fence_generation,
            capture_staging_ticket=staging_ticket,
            staged_ticket=staged_ticket,
            expected_capture_parts=expected_capture_parts,
            rejection_reason=rejection_reason,
        )

    async def _structural_row_passed(
        self, store: TaskObservationPort, workspace: str, envelope: ObservationEnvelope
    ) -> bool:
        """Report whether the structural FIFO has moved past this native row.

        That holds once the task store accepted the envelope and no outbox row
        or selected input can deliver it again. A row still queued after an
        interrupted delivery can consume a new handoff on its retry, and a
        delivery still in flight retires one it could not consume. An
        unreadable answer counts as passed: refusing one late handoff records an
        honest content gap, while staging it could strand a ticket.
        """

        probe = getattr(store, "structural_envelope_accepted", None)
        if not callable(probe):
            return False
        try:
            if probe(workspace, envelope) is False:
                return False
        except Exception:
            return True
        reader = getattr(self.local, "capture_handoff_structural_state", None)
        if not callable(reader):
            return True
        try:
            structural = cast(
                CaptureHandoffStructuralState, await self._local(partial(reader, workspace))
            )
        except Exception:
            return True
        key = (envelope.source.value, envelope.session_commitment, envelope.source_identity)
        return key not in structural.pending

    @staticmethod
    def _tombstone_capture_ticket(
        store: TaskObservationPort, ticket: ObservationCaptureTicket
    ) -> None:
        store.tombstone_capture_ticket(ticket)

    async def _retire_capture_ticket(
        self,
        workspace: str,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        ticket: ObservationCaptureTicket,
        *,
        delete: bool = False,
    ) -> None:
        """Retire one durable ticket, release its reservation, and confirm accounting."""

        if delete:
            store.delete_capture_ticket(ticket)
        else:
            self._tombstone_capture_ticket(store, ticket)
        await self._release_capture_ticket_reservation(workspace, runtime, ticket)
        confirmer = getattr(self.local, "confirm_capture_handoff_retirement", None)
        if callable(confirmer):
            await self._local(
                partial(
                    confirmer,
                    workspace,
                    observation_capture_ticket_id(ticket),
                    runtime.task_id,
                )
            )

    @staticmethod
    def _tombstone_capture_tickets(
        store: TaskObservationPort, workspace: str, profile: str | None = None
    ) -> None:
        """Fence durable handoffs without treating optional content as corrupt."""

        cleanup = getattr(store, "tombstone_capture_tickets", None)
        if callable(cleanup):
            cleanup(workspace, profile)

    async def _tombstone_capture_tickets_for_mapping(
        self,
        mapping: LifecycleMapping,
        workspace: str,
        profile: str | None = None,
    ) -> None:
        """Apply consent revocation to the mapped task before rejecting a hook."""

        runtime: TaskRuntime | None = None
        try:
            runtime, _ = await self._route_observation_mapping(
                mapping,
                required_capabilities=frozenset({RuntimeCapability.WRITE}),
            )
            store = self._observation_store(runtime)
            self._tombstone_capture_tickets(store, workspace, profile)
            await self._publish_capture_backlog(workspace, runtime, store)
        finally:
            if runtime is not None:
                await self.runtime.release(runtime)

    async def _tombstone_capture_ticket_for_request(
        self,
        mapping: LifecycleMapping,
        workspace: str,
        request: ObservationIngestRequest,
    ) -> None:
        """Fence only the native handoff proved by this authenticated hook row."""

        runtime: TaskRuntime | None = None
        try:
            runtime, _ = await self._route_observation_mapping(
                mapping,
                required_capabilities=frozenset({RuntimeCapability.WRITE}),
            )
            store = self._observation_store(runtime)
            logical_identity = observation_content_identity(request.envelope)
            ticket = store.load_capture_ticket(
                workspace=workspace,
                logical_identity=logical_identity,
            )
            if ticket is None or ticket.state not in {"staging", "pending"}:
                return
            # A valid Codex-session commitment alone is insufficient to retire
            # a durable handoff.  Match the task and the immutable native row
            # identity before changing ticket state; a stale/superseded row
            # must remain available for its own recovery path.
            if (
                ticket.task_id != runtime.task_id
                or ticket.session_commitment != request.envelope.session_commitment
                or ticket.source is not request.envelope.source
                or ticket.source_identity != request.envelope.source_identity
                or ticket.cursor != request.envelope.cursor
                or (
                    request.content_capture_profile is not None
                    and ticket.content_capture_profile != request.content_capture_profile
                )
            ):
                return
            await self._retire_capture_ticket(workspace, runtime, store, ticket)
            await self._publish_capture_backlog(workspace, runtime, store)
        finally:
            if runtime is not None:
                await self.runtime.release(runtime)

    async def _capture_budget_refusal_context(
        self,
        workspace: str,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        request: ObservationIngestRequest,
    ) -> _NativeCaptureContext:
        """Retire only this failed handoff and continue its structural evidence."""

        identity = observation_content_identity(request.envelope)
        loader = getattr(store, "load_capture_ticket", None)
        if callable(loader):
            ticket = loader(workspace=workspace, logical_identity=identity)
            if (
                type(ticket) is ObservationCaptureTicket
                and ticket.task_id == runtime.task_id
                and ticket.source is request.envelope.source
                and ticket.session_commitment == request.envelope.session_commitment
                and ticket.source_identity == request.envelope.source_identity
                and ticket.cursor == request.envelope.cursor
                and ticket.state in {"staging", "pending"}
            ):
                await self._retire_capture_ticket(workspace, runtime, store, ticket)
        return _NativeCaptureContext(
            native_source=request.envelope.source
            in {
                ObservationSource.CODEX_HOOK,
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CURSOR_HOOK,
            },
            requested_content_profile=request.content_capture_profile,
            content_identity=identity,
            pending_capture_ticket=None,
            content_authorized=False,
            content_authorization_missing=False,
            content_capture_blocked=True,
            capture_ticket_revoked=False,
            native_content_requested=bool(request.content_chunks),
            capture_fence=None,
            fence_generation=None,
            capture_staging_ticket=None,
            staged_ticket=None,
            expected_capture_parts=None,
            rejection_reason=None,
        )

    async def ingest_request(self, request: ObservationIngestRequest) -> ObservationIngestResult:
        """Coordinator ingest path used by ordinary-control ``observation_ingest``."""

        if not self.observation_enabled:
            if type(request) is not ObservationIngestRequest:
                return _reject("observation_disabled")
            if request.envelope.source not in {
                ObservationSource.CODEX_HOOK,
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CURSOR_HOOK,
            }:
                # Session-stream envelopes cannot carry capture tickets. Keep
                # their disabled path inert before resolving any task route.
                return _reject("observation_disabled")
        if type(request) is not ObservationIngestRequest:
            return _reject(ObservationGapCode.CONSENT_MISSING.value)
        try:
            selection_route = observation_selection_route(request.envelope.structural_payload)
        except ProtocolValueError:
            return _reject(
                ObservationGapCode.SELECTION_ROUTE_CHANGED.value,
                request.envelope.cursor,
            )
        try:
            codex_session_id = validate_codex_session_id(request.codex_session_id)
        except ProtocolValueError:
            return _reject(ObservationGapCode.CONSENT_MISSING.value)

        key_material = await self._local(self.local.key_material)
        expected = session_commitment_from_codex_id(key_material, codex_session_id)
        if request.envelope.session_commitment != expected:
            return _reject(ObservationGapCode.CONSENT_MISSING.value)
        if codex_session_id in self._storage_corrupt_sessions:
            return _reject(ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)

        mapping = self.mapping_loader(codex_session_id, _state=self.state_root)
        if mapping is None:
            return _reject(ObservationGapCode.MAPPING_MISSING.value)
        predecessor_session_id = mapping.yoetz_session_id
        predecessor_writer_id = mapping.yoetz_writer_id

        workspace = await self._local(
            partial(self.local.find_workspace_for_codex_session, codex_session_id)
        )
        if workspace is None:
            return _reject(ObservationGapCode.CONSENT_MISSING.value)
        consent = await self._local(partial(self.local.consent_for, workspace))
        if not self.observation_enabled:
            # A native capture ticket can outlive the runtime admission switch:
            # the READY sweeper still replays its structural row after the
            # switch is disabled.  Validate the session commitment, mapping,
            # and workspace above before fencing the mapped task's unfinished
            # handoffs.  Restrict this maintenance to native envelopes so a
            # structurally valid non-native request cannot revoke unrelated
            # native tickets merely by sharing the session commitment.
            if request.envelope.source in {
                ObservationSource.CODEX_HOOK,
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CURSOR_HOOK,
            }:
                try:
                    await self._tombstone_capture_ticket_for_request(mapping, workspace, request)
                except PublicOperationError as exc:
                    if exc.code is PublicErrorCode.STORAGE_CORRUPT:
                        return _reject(ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)
                    return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
                except Exception:
                    return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            return _reject("observation_disabled")
        if consent is None or not consent.active:
            reason = (
                ObservationGapCode.CONSENT_REVOKED.value
                if consent is not None and consent.revoked_at is not None
                else (
                    "paused"
                    if consent is not None and consent.paused
                    else ObservationGapCode.CONSENT_MISSING.value
                )
            )
            try:
                await self._tombstone_capture_tickets_for_mapping(mapping, workspace)
            except PublicOperationError as exc:
                if exc.code is PublicErrorCode.STORAGE_CORRUPT:
                    return _reject(ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)
                return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            except Exception:
                return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            return _reject(reason)

        # Native capture-only requests are a short, durable handoff lane. They
        # must be able to stage content while an older structural row is still
        # in ledger replay/advice, but all object/manifest writes remain
        # serialized by ``_capture_lock`` below. Structural requests retain
        # the existing coordinator lock for their full ledger path.
        request_lock = self._capture_lock if request.capture_only else self._lock
        async with request_lock:
            if codex_session_id in self._storage_corrupt_sessions:
                return _reject(ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)
            runtime: TaskRuntime | None = None
            store: TaskObservationPort | None = None
            route_history: list[LifecycleMapping] = []
            completed_ingest: (
                tuple[TaskRuntime, ObservationEnvelope, ObservationIngestResult, bool] | None
            ) = None
            stage = "runtime_route"
            handoff = _StructuralCaptureHandoff()
            try:
                runtime, mapping = await self._route_observation_mapping(
                    mapping, route_history=route_history
                )
                legacy_writer_routes, route_history_truncated = _observation_writer_routes(
                    runtime, route_history, state_root=self.state_root
                )
                stage = "store_prepare"
                store = self._observation_store(runtime)
                if consent.content_capture_profiles:
                    store.grant_consent(
                        workspace,
                        consent.granted_at,
                        content_capture_profiles=consent.content_capture_profiles,
                    )
                else:
                    # Keep compatibility with test/reference task stores and
                    # pre-0010 bundles for the historical structural arm. A
                    # native content request still requires the new store API
                    # below, so this fallback can never authorize content.
                    try:
                        store.grant_consent(
                            workspace,
                            consent.granted_at,
                            content_capture_profiles=(),
                        )
                    except TypeError:
                        store.grant_consent(workspace, consent.granted_at)
                if selection_route is not None:
                    authority = await self._local(
                        partial(self.local.content_capture_authority, workspace)
                    )
                    if not _selection_route_is_current(
                        selection_route,
                        runtime,
                        legacy_writer_routes,
                        authority_generation=(
                            authority.generation if authority is not None else None
                        ),
                        authority_active=bool(authority is not None and authority.active),
                    ):
                        return _reject(
                            ObservationGapCode.SELECTION_ROUTE_CHANGED.value,
                            request.envelope.cursor,
                        )
                store.bind_session(workspace, request.envelope.session_commitment)
                # A post-generation-bump stream completion names its hook call's generation.
                # Resolve that before the captured-content lookup and the materialization, which
                # both key on the call's generation-qualified identity (#1019, #1027). The
                # ingested envelope keeps the stream's own cursor: the store dedupes on it.
                stage = "generation_align"
                capture_envelope = (
                    request.envelope
                    if request.capture_only
                    else await self._align_codex_stream_generation(
                        runtime, workspace, request.envelope
                    )
                )
                stage = "store_prepare"
                capture_lock_owned = request.capture_only
                if not capture_lock_owned:
                    await self._capture_lock.acquire()
                try:
                    self._capture_budget_exhausted = False
                    try:
                        capture = await self._native_capture_context(
                            runtime,
                            store,
                            workspace=workspace,
                            request=request,
                            consent=consent,
                            admitted_ticket_session_ids=frozenset(
                                {runtime.session_id}
                                | {session_id for session_id, _writer_id in legacy_writer_routes}
                            ),
                        )
                    except PublicOperationError as exc:
                        if exc.code is not PublicErrorCode.LIMIT_EXCEEDED:
                            raise
                        self._capture_budget_exhausted = True
                        for code in (
                            ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value,
                            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                        ):
                            await self._local(
                                partial(self.local.note_coverage_gap, workspace, code)
                            )
                        capture = await self._capture_budget_refusal_context(
                            workspace, runtime, store, request
                        )
                        if request.capture_only:
                            return _reject(ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value)
                    if capture.rejection_reason is not None:
                        return _reject(capture.rejection_reason)
                    native_content_source = capture.native_source
                    content_identity = capture.content_identity
                    content_authorized = capture.content_authorized
                    content_authorization_missing = capture.content_authorization_missing
                    content_capture_blocked = capture.content_capture_blocked
                    capture_ticket_revoked = capture.capture_ticket_revoked
                    capture_fence = capture.capture_fence
                    fence_generation = capture.fence_generation
                    capture_staging_ticket = capture.capture_staging_ticket
                    staged_ticket = capture.staged_ticket
                    expected_capture_parts = capture.expected_capture_parts
                    handoff.bind(request, capture)
                    if content_capture_blocked or capture_ticket_revoked:
                        captured_content = ()
                        replay_content_candidates = ()
                        content_redacted = False
                        content_unavailable = True
                    else:
                        capture_chunks = request.content_chunks if content_authorized else ()
                        capture_result = await self._capture_content(
                            runtime,
                            store,
                            workspace=workspace,
                            envelope=capture_envelope,
                            chunks=capture_chunks,
                            capture_fence=capture_fence,
                            expected_capture_parts=expected_capture_parts,
                            allow_incomplete_recovery=capture_staging_ticket is not None,
                            source_qualified_capture=(
                                request.capture_only
                                or capture_staging_ticket is not None
                                or staged_ticket is not None
                            ),
                        )
                        (
                            captured_content,
                            replay_content_candidates,
                            content_redacted,
                            content_unavailable,
                        ) = capture_result
                    capture_budget_exhausted = self._capture_budget_exhausted
                    if (
                        captured_content
                        and not content_unavailable
                        and capture_fence is not None
                        and not await capture_fence()
                    ):
                        captured_content = ()
                        content_unavailable = True
                        capture_ticket_revoked = True
                        if staged_ticket is not None:
                            await self._retire_capture_ticket(
                                workspace, runtime, store, staged_ticket
                            )
                            staged_ticket = None
                    if capture_staging_ticket is not None and (
                        not captured_content or content_unavailable
                    ):
                        await self._retire_capture_ticket(
                            workspace, runtime, store, capture_staging_ticket
                        )
                        capture_ticket_revoked = True
                    if (
                        native_content_source
                        and content_identity is not None
                        and fence_generation is not None
                        and captured_content
                        and not content_unavailable
                    ):
                        complete_ticket = (
                            replace(
                                capture_staging_ticket,
                                object_ids=tuple(item.object_id for item in captured_content),
                                state="pending",
                                expected_parts=expected_capture_parts or (),
                            )
                            if capture_staging_ticket is not None
                            else None
                        )
                        if complete_ticket is not None:
                            assert capture_staging_ticket is not None
                            try:
                                store.finalize_capture_ticket(
                                    capture_staging_ticket, complete_ticket
                                )
                            except PublicOperationError as exc:
                                if exc.code is not PublicErrorCode.LIMIT_EXCEEDED:
                                    raise
                                # A legacy or hand-written manifest set may
                                # have crossed the object boundary without a
                                # current budget admission. Retire the
                                # staging fence and continue with an honest
                                # content-unavailable structural observation.
                                await self._retire_capture_ticket(
                                    workspace, runtime, store, capture_staging_ticket
                                )
                                capture_staging_ticket = None
                                captured_content = ()
                                content_unavailable = True
                                capture_ticket_revoked = True
                                self._capture_budget_exhausted = True
                                await self._local(
                                    partial(
                                        self.local.note_coverage_gap,
                                        workspace,
                                        ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value,
                                    )
                                )
                                await self._local(
                                    partial(
                                        self.local.note_coverage_gap,
                                        workspace,
                                        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                                    )
                                )
                            else:
                                staged_ticket = complete_ticket
                                if capture_fence is not None and not await capture_fence():
                                    await self._retire_capture_ticket(
                                        workspace, runtime, store, staged_ticket
                                    )
                                    staged_ticket = None
                                    captured_content = ()
                                    content_unavailable = True
                                    capture_ticket_revoked = True
                        elif staged_ticket is None:
                            raise PublicOperationError(
                                PublicErrorCode.STORAGE_CORRUPT,
                                "Observation capture ticket is unavailable.",
                                retryable=False,
                            )
                    if request.capture_only:
                        if staged_ticket is None:
                            return _reject(
                                ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value
                                if capture_budget_exhausted
                                else ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
                            )
                        return _reject(OBSERVATION_CONTENT_CAPTURE_PENDING_REASON)
                finally:
                    if not capture_lock_owned:
                        self._capture_lock.release()
                if capture_fence is not None and not await capture_fence():
                    if staged_ticket is not None:
                        await self._retire_capture_ticket(workspace, runtime, store, staged_ticket)
                        staged_ticket = None
                    captured_content = ()
                    content_unavailable = True
                    capture_ticket_revoked = True
                gaps = set(request.envelope.gap_codes)
                if content_redacted:
                    gaps.add(ObservationGapCode.CONTENT_REDACTED.value)
                if content_unavailable:
                    gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
                if content_authorization_missing:
                    gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
                if capture_budget_exhausted:
                    gaps.add(ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value)
                    gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
                if request.envelope.event_kind in {
                    "SubagentStart",
                    "subagent_start",
                    "subagentStart",
                    "SubagentStop",
                    "subagent_stop",
                    "subagentStop",
                }:
                    missing_identity = ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value
                    gaps.discard(missing_identity)
                    if host_lineage_from_envelope(request.envelope) is None:
                        gaps.add(missing_identity)
                elif (
                    request.envelope.source is ObservationSource.CODEX_HOOK
                    and request.envelope.event_kind == "PostToolUse"
                    and "lineage_child_task_id" in request.envelope.structural_payload
                    and _native_child_start_observation(request.envelope) is None
                ):
                    # Retain the gap in the task ledger before the optional registry sidecar.
                    gaps.add(ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value)
                envelope = replace(
                    request.envelope,
                    content_object_refs=tuple(
                        sorted(
                            {
                                *request.envelope.content_object_refs,
                                *(item.object_id for item in captured_content),
                            },
                            key=str.encode,
                        )
                    ),
                    gap_codes=tuple(sorted(gaps, key=str.encode)),
                )
                stage = "store_ingest"
                result = await store.ingest(envelope)
                if result.disposition is ObservationIngestDisposition.REJECTED:
                    if result.reason not in _CAPTURE_TICKET_RETRYABLE_REJECTION_REASONS:
                        # A terminal store refusal retires this handoff. Leaving a pending
                        # ticket behind after a stale/consent/schema rejection would make the
                        # structural outbox terminal while every later freeze remains blocked
                        # by an unconsumable capture ticket. Restrict cleanup to the exact ticket
                        # admitted for this envelope; retryable coordination keeps it durable.
                        for ticket in (staged_ticket, capture_staging_ticket):
                            if ticket is not None and ticket.state in {"staging", "pending"}:
                                # Account and disclose before the tombstone (#1019): a ticket
                                # whose marker is not durable yet stays listed, so a later
                                # reconciliation pass retires it and publishes the marker.
                                if await self._record_capture_handoff_retirement(
                                    workspace,
                                    ticket,
                                    stage=CaptureHandoffRetirementStage.STRUCTURAL_REFUSED,
                                    reason=CaptureHandoffRetirementReason.TERMINAL_REFUSAL,
                                ) and await self._publish_capture_handoff_retirement(
                                    runtime,
                                    ticket,
                                    CaptureHandoffRetirementReason.TERMINAL_REFUSAL,
                                ):
                                    await self._retire_capture_ticket(
                                        workspace, runtime, store, ticket
                                    )
                                break
                        # A matched handoff this delivery never staged (content
                        # blocked or unauthorized) is stranded as well (#836).
                        await self._retire_stranded_capture_handoff(
                            workspace,
                            runtime,
                            store,
                            handoff,
                            stage=CaptureHandoffRetirementStage.STRUCTURAL_REFUSED,
                            reason=CaptureHandoffRetirementReason.TERMINAL_REFUSAL,
                        )
                    return result

                # Persist the host/session binding at native admission, before optional lineage,
                # verification, or advice work can fail.  The mapping selected above is the
                # request's original route; a retired predecessor may have been followed to a
                # successor runtime, in which case this returns False and the envelope remains
                # structural evidence only.
                stage = "host_session_route"
                route_bound = await self._record_current_host_session_route(
                    runtime,
                    store,
                    workspace=workspace,
                    codex_session_id=codex_session_id,
                    envelope=envelope,
                    expected_session_id=predecessor_session_id,
                    expected_writer_id=predecessor_writer_id,
                )

                # Keep host attribution in the service-owned catalog alongside the local
                # envelope. ACCEPTED and DUPLICATE both pass through this idempotent path so a
                # restart or a prior partial failure can repair a missing annotation before
                # reporting success.
                stage = "host_lineage"
                await self._record_host_lineage(
                    runtime, workspace, envelope, writer_routes=legacy_writer_routes
                )

                # ACCEPTED and DUPLICATE both reconcile the durable ledger before
                # reporting success. A DUPLICATE is never an early return: the
                # observation row may already exist while a prior ledger append
                # failed, so re-run the idempotent materialize/append to repair it.
                # If any step raises, the broad guard below turns it into a
                # retryable rejection so the outbox keeps the entry pending.
                # A post-compaction stream completion materializes under its hook call's
                # generation so the pair folds into one action (#1019). The ingested
                # envelope is restored before verification and advice.
                ingested_envelope = envelope
                if capture_envelope.cursor.source_generation != envelope.cursor.source_generation:
                    envelope = replace(
                        envelope,
                        cursor=replace(
                            envelope.cursor,
                            source_generation=capture_envelope.cursor.source_generation,
                        ),
                    )
                batch = materialize_observation_envelope(
                    envelope,
                    task_id=runtime.task_id,
                    captured_content=captured_content,
                )
                if batch.skip_reason == ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value:
                    # Persist this permanent loss even though no ledger evidence or annotation
                    # can safely be attributed. DUPLICATE retries repair an interrupted write.
                    await self._local(
                        partial(
                            self.local.note_coverage_gap,
                            workspace,
                            ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value,
                        )
                    )
                if batch.skip_reason is None and batch.drafts:
                    replay_role_sets: list[tuple[str, ...]] = []
                    # The inverse lost-order case is contentless first, then an
                    # equivalent copy with content. Its immutable core operation
                    # must win over a second operation that would remint the same
                    # core event ids. The late content remains stored but cannot
                    # retroactively strengthen that committed operation.
                    core_batch = materialize_observation_envelope(
                        replace(envelope, content_object_refs=()),
                        task_id=runtime.task_id,
                        captured_content=(),
                    )
                    if core_batch.skip_reason is None and core_batch.drafts:
                        replay_role_sets.append(tuple(item.role for item in core_batch.drafts))
                    # A historical Claude/Cursor post-only false positive was
                    # committed as unpaired evidence before the explicit host
                    # contract existed. Rebuild that role set from the
                    # retained gap itself, even when no captured manifest is
                    # available to supply a replay candidate.
                    legacy_unpaired = _legacy_unpaired_replay_envelope(envelope)
                    if legacy_unpaired is not None:
                        legacy_core_batch = materialize_observation_envelope(
                            legacy_unpaired,
                            task_id=runtime.task_id,
                            captured_content=(),
                        )
                        legacy_roles = tuple(item.role for item in legacy_core_batch.drafts)
                        if (
                            legacy_core_batch.skip_reason is None
                            and legacy_roles
                            and legacy_roles not in replay_role_sets
                        ):
                            replay_role_sets.append(legacy_roles)
                    for candidate in replay_content_candidates:
                        replay_envelope = replace(
                            envelope,
                            content_object_refs=tuple(
                                sorted(
                                    (item.object_id for item in candidate),
                                    key=str.encode,
                                )
                            ),
                        )
                        replay_batch = materialize_observation_envelope(
                            replay_envelope,
                            task_id=runtime.task_id,
                            captured_content=candidate,
                        )
                        roles = tuple(item.role for item in replay_batch.drafts)
                        if (
                            replay_batch.skip_reason is None
                            and roles
                            and roles not in replay_role_sets
                        ):
                            replay_role_sets.append(roles)
                        if legacy_unpaired is not None:
                            legacy_replay_batch = materialize_observation_envelope(
                                replace(
                                    legacy_unpaired,
                                    content_object_refs=replay_envelope.content_object_refs,
                                ),
                                task_id=runtime.task_id,
                                captured_content=candidate,
                            )
                            legacy_replay_roles = tuple(
                                item.role for item in legacy_replay_batch.drafts
                            )
                            if (
                                legacy_replay_batch.skip_reason is None
                                and legacy_replay_roles
                                and legacy_replay_roles not in replay_role_sets
                            ):
                                replay_role_sets.append(legacy_replay_roles)
                    # One logical action per paired host call (#917). The pre and
                    # the post (and their hook/stream copies) name the same
                    # action; the phase appended first records it and the other
                    # links its result and evidence to it. Both committed shapes
                    # stay lookup candidates so a replay finds its own operation.
                    stage = "action_link"
                    action_plan = await self._plan_action_link(
                        runtime,
                        envelope=envelope,
                        batch=batch,
                        replay_role_sets=tuple(replay_role_sets),
                    )
                    batch = action_plan.batch
                    replay_role_sets.extend(action_plan.role_sets)
                    replay_claims: list[
                        tuple[ObservationLogicalIdentityClaim, tuple[str, ...]]
                    ] = []
                    if route_history_truncated:
                        candidate_role_sets = tuple(
                            dict.fromkeys(
                                (
                                    tuple(item.role for item in batch.drafts),
                                    *replay_role_sets,
                                )
                            )
                        )
                        for candidate_mapping_version in (
                            MATERIALIZATION_MAPPING_VERSION,
                            *MATERIALIZATION_LEGACY_MAPPING_VERSIONS,
                        ):
                            for candidate_roles in candidate_role_sets:
                                claim = _load_logical_identity_claim(
                                    store,
                                    workspace=workspace,
                                    logical_identity=observation_claim_identity(
                                        envelope,
                                        candidate_roles,
                                        mapping_version=candidate_mapping_version,
                                    ),
                                )
                                if claim is not None:
                                    replay_claims.append((claim, candidate_roles))
                    stage = "ledger_append"
                    replay_required = route_history_truncated and (
                        result.disposition is ObservationIngestDisposition.DUPLICATE
                        or bool(replay_claims)
                    )
                    if action_plan.skip:
                        # The call's action is already recorded by its other
                        # phase and this phase carries nothing else to append.
                        claim = None
                    elif captured_content:
                        claim = await self._append_materialized(
                            runtime,
                            envelope,
                            batch,
                            captured_content=captured_content,
                            legacy_session_id=predecessor_session_id,
                            legacy_writer_id=predecessor_writer_id,
                            legacy_writer_routes=legacy_writer_routes,
                            replay_required=replay_required,
                            replay_claims=tuple(replay_claims),
                            replay_draft_role_sets=tuple(replay_role_sets),
                        )
                    else:
                        # Keep the structural-only override seam compatible with
                        # older in-process coordinators and test doubles.
                        claim = await self._append_materialized(
                            runtime,
                            envelope,
                            batch,
                            legacy_session_id=predecessor_session_id,
                            legacy_writer_id=predecessor_writer_id,
                            legacy_writer_routes=legacy_writer_routes,
                            replay_required=replay_required,
                            replay_claims=tuple(replay_claims),
                            replay_draft_role_sets=tuple(replay_role_sets),
                        )
                    if isinstance(claim, _AlreadyCommitted):
                        # Every event of this delivery is already recorded, under another
                        # delivery's operation (#1027). Nothing is appended and no claim is
                        # written; a stream completion's explicit outcome still reaches the
                        # recorded action, exactly as on a replay.
                        stage = "ledger_append"
                        await self._correct_recorded_outcome(
                            runtime,
                            workspace,
                            store,
                            codex_session_id,
                            envelope,
                            batch,
                            resolved_mapping_version=MATERIALIZATION_MAPPING_VERSION,
                            append_result=None,
                            already_committed=True,
                            legacy_session_id=predecessor_session_id,
                            legacy_writer_id=predecessor_writer_id,
                            legacy_writer_routes=legacy_writer_routes,
                        )
                        claim = None
                    if claim is not None:
                        (
                            operation_id,
                            materialization_digest,
                            append_result,
                            resolved_mapping_version,
                            resolved_draft_roles,
                        ) = claim
                        current_draft_roles = tuple(item.role for item in batch.drafts)
                        if not action_plan.same_content_roles(
                            resolved_draft_roles, current_draft_roles
                        ):
                            await self._local(
                                partial(
                                    self.local.note_coverage_gap,
                                    workspace,
                                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                                )
                            )
                        # The claim key is role-scoped so the phases of one host
                        # call (pre action, paired result, permission, subagent)
                        # never contend, and the recorded mapping version is the
                        # source-independent materialization one so hook/stream
                        # copies of a phase can union their source masks. Every
                        # hook source (Codex, Claude Code, Cursor) is the hook
                        # bit; only the Codex session stream is the stream bit.
                        stage = "identity_claim"
                        store.record_logical_identity_claim(
                            workspace=workspace,
                            logical_identity=observation_claim_identity(
                                envelope,
                                resolved_draft_roles,
                                mapping_version=resolved_mapping_version,
                            ),
                            materialization_digest=materialization_digest,
                            operation_id=operation_id,
                            source_mask=(
                                2
                                if envelope.source is ObservationSource.CODEX_SESSION_STREAM
                                else 1
                            ),
                            mapping_version=resolved_mapping_version,
                            materialized_at=timestamp_from_datetime(self.clock.now_utc()),
                        )
                        stage = "ledger_append"
                        if append_result is not None:
                            await self._note_frontier_motion(
                                runtime,
                                workspace,
                                codex_session_id,
                                append_result,
                            )
                        await self._correct_recorded_outcome(
                            runtime,
                            workspace,
                            store,
                            codex_session_id,
                            envelope,
                            batch,
                            resolved_mapping_version=resolved_mapping_version,
                            append_result=append_result,
                            already_committed=False,
                            legacy_session_id=predecessor_session_id,
                            legacy_writer_id=predecessor_writer_id,
                            legacy_writer_routes=legacy_writer_routes,
                        )

                envelope = ingested_envelope
                stage = "verification"
                await self._enqueue_verification(
                    runtime,
                    workspace,
                    store,
                    envelope,
                    codex_session_id=codex_session_id,
                    legacy_session_id=predecessor_session_id,
                    legacy_writer_id=predecessor_writer_id,
                )
                stage = "advice"
                await self._run_advice(
                    workspace,
                    runtime,
                    store,
                    legacy_writer_id=predecessor_writer_id,
                    session_commitment=envelope.session_commitment,
                )
                if staged_ticket is not None:
                    # The ledger/materialization path above has completed. A
                    # retry ticket is no longer needed, and deleting it now
                    # keeps a committed phase from being mistaken for a
                    # still-pending handoff. Any exception before this point
                    # leaves the ticket durable for restart/retry.
                    await self._retire_capture_ticket(
                        workspace, runtime, store, staged_ticket, delete=True
                    )
                # Once this row is acknowledged nothing else can consume its
                # handoff. Retire one it matched but could not consume (content
                # blocked, unauthorized, or fenced) or one staged while it was in
                # flight, instead of leaving a ticket that holds capture pressure
                # and blocks new checks (#836).
                await self._retire_stranded_capture_handoff(
                    workspace,
                    runtime,
                    store,
                    handoff,
                    stage=CaptureHandoffRetirementStage.STRUCTURAL_COMMITTED,
                    reason=CaptureHandoffRetirementReason.CONTENT_NOT_ADMITTED,
                )
                completed_ingest = (runtime, envelope, result, route_bound)
            except PublicOperationError as exc:
                if exc.retryable and exc.code in {
                    PublicErrorCode.OPERATION_PENDING,
                    PublicErrorCode.BUNDLE_BUSY,
                    PublicErrorCode.FRONTIER_CONFLICT,
                }:
                    # Designed back-pressure, not a failure (#351). ADR-022
                    # decision 4 makes observation appends receive retryable
                    # OPERATION_PENDING while check acquisition or a frozen-case
                    # barrier is active; BUNDLE_BUSY and FRONTIER_CONFLICT are
                    # the same transient coordination one layer down. The
                    # durable outbox keeps the row pending and retries after the
                    # barrier clears, so no unexpected-exception diagnostic is
                    # recorded and no service_unavailable gap is projected.
                    return _reject(OBSERVATION_BACKPRESSURE_REASON)
                record_unexpected_exception_without_raising(
                    exc,
                    component="application.observation_coordinator",
                    operation=(f"observation_ingest_{stage}_{exc.code.value.lower()}"),
                )
                if exc.code is PublicErrorCode.STORAGE_CORRUPT:
                    if stage == "identity_claim":
                        # A conflicting logical-identity claim poisons one
                        # envelope, not the bundle. ADR-010 scopes the
                        # generation latch to bundle corruption, so reject just
                        # this envelope and keep the session observable.
                        await self._retire_stranded_capture_handoff(
                            workspace,
                            runtime,
                            store,
                            handoff,
                            stage=CaptureHandoffRetirementStage.STRUCTURAL_REFUSED,
                            reason=CaptureHandoffRetirementReason.TERMINAL_REFUSAL,
                        )
                        return _reject(ObservationGapCode.DEDUP_CONFLICT.value)
                    self._storage_corrupt_sessions.add(codex_session_id)
                    await self._retire_stranded_capture_handoff(
                        workspace,
                        runtime,
                        store,
                        handoff,
                        stage=CaptureHandoffRetirementStage.STRUCTURAL_REFUSED,
                        reason=CaptureHandoffRetirementReason.TERMINAL_REFUSAL,
                    )
                    return _reject(ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)
                if (
                    exc.code is PublicErrorCode.SESSION_NOT_FOUND
                    and exc.safe_details.get("reason_code") == "session_superseded"
                ):
                    # Followable retirement is consumed in
                    # `_route_observation_mapping`. A payload that cannot be
                    # followed, a hop cycle, or a rotation after the route
                    # opened is route retirement, not a missing mapping file
                    # and not a ledger content refusal (#577).
                    await self._retire_stranded_capture_handoff(
                        workspace,
                        runtime,
                        store,
                        handoff,
                        stage=CaptureHandoffRetirementStage.STRUCTURAL_REFUSED,
                        reason=CaptureHandoffRetirementReason.TERMINAL_REFUSAL,
                    )
                    return _reject(ObservationGapCode.SESSION_SUPERSEDED.value)
                if (
                    exc.code is PublicErrorCode.SESSION_CONFLICT
                    and not exc.retryable
                    and stage == "runtime_route"
                ):
                    # A route conflict means the cached lifecycle mapping cannot currently be
                    # used. Keep the observation pending so the next drain can recover a
                    # successor mapping. A conflict raised after routing remains terminal: it
                    # is then a storage or ledger refusal rather than route recovery.
                    return _reject(ObservationGapCode.MAPPING_MISSING.value)
                if not exc.retryable:
                    # Validation and identity rejections are terminal by their
                    # public contract. Calling them service_unavailable made a
                    # healthy daemon look down and left the FIFO head immortal
                    # because every drain path retried it (#540). That includes
                    # SESSION_NOT_FOUND without a followable binding and
                    # non-retryable SESSION_CONFLICT after the narrower route
                    # recovery case above (#554).
                    await self._retire_stranded_capture_handoff(
                        workspace,
                        runtime,
                        store,
                        handoff,
                        stage=CaptureHandoffRetirementStage.STRUCTURAL_REFUSED,
                        reason=CaptureHandoffRetirementReason.TERMINAL_REFUSAL,
                    )
                    return _reject(ObservationGapCode.LEDGER_REJECTED.value)
                if exc.code is PublicErrorCode.VAULT_LOCKED:
                    return _reject(ObservationGapCode.VAULT_LOCKED.value)
                # Any other retryable public failure is transient coordination
                # with no narrower class; the row stays pending under the
                # consecutive-rejection ceiling (#539).
                return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="application.observation_coordinator",
                    operation=f"observation_ingest_{stage}_failed",
                )
                return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            finally:
                if runtime is not None:
                    try:
                        if store is not None:
                            await self._publish_capture_backlog(workspace, runtime, store)
                    finally:
                        # Feedback may be cancelled or fail. It never owns the runtime lease,
                        # so that failure must not strand the bundle and block the next attach.
                        with_context = getattr(self.runtime, "release", None)
                        if with_context is not None:
                            # A second disconnect cancellation must not interrupt release
                            # while it waits for the runtime registry lock.
                            pending = asyncio.ensure_future(with_context(runtime))
                            self._pending_releases.add(pending)
                            pending.add_done_callback(self._release_finished)
                            await asyncio.shield(pending)
            completed_runtime, completed_envelope, completed_result, route_bound = completed_ingest
            try:
                # Never wait for the lineage mutation lock while retaining a runtime lease:
                # attach holds that lock while it waits to rebind the same runtime.
                await self._renew_observed_activity(
                    completed_runtime,
                    completed_envelope,
                    disposition=completed_result.disposition,
                    predecessor_session_id=predecessor_session_id,
                    predecessor_writer_id=predecessor_writer_id,
                    route_bound=route_bound,
                    workspace=workspace,
                    codex_session_id=codex_session_id,
                )
                await self._sweep_lineage(completed_runtime.task_id)
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="application.observation_coordinator",
                    operation="observation_ingest_lineage_failed",
                )
                return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            return completed_result

    async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
        """ObservationPort-shaped ingest without Codex session id → reject closed."""

        del envelope
        return _reject(ObservationGapCode.MAPPING_MISSING.value)

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
        return await self._local(partial(self.local.status, query))

    async def pause(self, command: ObservationControlCommand) -> ObservationStatus:
        return await self._local(partial(self.local.pause, command))

    async def resume(self, command: ObservationControlCommand) -> ObservationStatus:
        return await self._local(partial(self.local.resume, command))

    async def revoke(self, command: ObservationRevokeCommand) -> ObservationStatus:
        async with self._lock:
            # The local fence is authoritative for immediately stopping new capture. The pending
            # token is durable before any project/catalog await, so a crash here cannot be
            # mistaken for a completed revocation after a later re-consent.
            status = await self._local(partial(self.local.revoke, command))
            pending = await self._local(
                partial(self.local.pending_consent_revocation, command.workspace_commitment)
            )

            seen_tasks: set[str] = set()
            mappings_by_task: dict[str, LifecycleMapping] = {}
            revoked_sessions = await self._local(
                partial(self.local.codex_sessions_for_workspace, command.workspace_commitment)
            )
            task_ids: list[str] = []
            for codex_session_id in revoked_sessions:
                mapping = self.mapping_loader(codex_session_id, _state=self.state_root)
                if mapping is None or mapping.yoetz_task_id in seen_tasks:
                    continue
                seen_tasks.add(mapping.yoetz_task_id)
                task_ids.append(mapping.yoetz_task_id)
                mappings_by_task[mapping.yoetz_task_id] = mapping

            planner = self.consent_invalidation_planner
            applier = self.consent_invalidation_applier
            if pending is not None:
                token, recorded_generations = pending
                if planner is None or applier is None:
                    # Standalone/local compositions have no project catalog to fence. READY
                    # always binds both callbacks; this fallback preserves local revoke behavior.
                    await self._local(
                        partial(
                            self.local.mark_consent_revocation_fenced,
                            command.workspace_commitment,
                            token,
                        )
                    )
                else:
                    if recorded_generations is not None:
                        plan = SourceConsentRevocationPlan(token, recorded_generations)
                    else:
                        plan = await planner(
                            tuple(sorted(task_ids, key=str.encode)),
                            command.workspace_commitment,
                            token,
                        )
                        await self._local(
                            partial(
                                self.local.record_consent_revocation_plan,
                                command.workspace_commitment,
                                token,
                                dict(plan.project_generations),
                            )
                        )
                    await applier(plan)
                    await self._local(
                        partial(
                            self.local.mark_consent_revocation_fenced,
                            command.workspace_commitment,
                            token,
                        )
                    )

            # Bundle propagation additionally deactivates encrypted locator/trust rows while
            # retaining evidence. It runs after the project fence so old-generation advice cannot
            # win a delivery race.
            for task_id in sorted(task_ids, key=str.encode):
                mapping = mappings_by_task.get(task_id)
                if mapping is None:
                    continue
                runtime: TaskRuntime | None = None
                try:
                    runtime, mapping = await self._route_observation_mapping(
                        mapping,
                        required_capabilities=frozenset({RuntimeCapability.WRITE}),
                    )
                    await self._observation_store(runtime).revoke(command)
                except Exception:
                    await self._local(
                        partial(
                            self.local.note_coverage_gap,
                            command.workspace_commitment,
                            ObservationGapCode.SERVICE_UNAVAILABLE.value,
                        )
                    )
                finally:
                    if runtime is not None:
                        await self.runtime.release(runtime)
            return status

    def _observation_store(self, runtime: TaskRuntime) -> TaskObservationPort:
        store = runtime.observation
        if store is None:
            raise PublicOperationError(
                PublicErrorCode.STORAGE_UNSAFE,
                "Observation store connection is unavailable.",
                retryable=True,
            )
        return store

    async def _record_current_host_session_route(
        self,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        *,
        workspace: str,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        expected_session_id: str,
        expected_writer_id: str,
    ) -> bool:
        """Persist the current host binding before liveness can use the envelope.

        Lifecycle recovery can rewrite an ended host mapping to a successor Yoetz session.  An
        envelope drained from that predecessor must therefore remain structural evidence only: its
        ended host-session fence is checked before a route write, and the observation adapter's
        first-writer commitment fence refuses a conflicting host binding for an existing Yoetz
        session.  A missing route recorder is retained for compatibility doubles; READY has the
        durable implementation.
        """

        if (
            envelope.source
            not in {
                ObservationSource.CODEX_HOOK,
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CURSOR_HOOK,
            }
            or envelope.event_kind == "SessionEnd"
            or runtime.writer_id is None
            or runtime.session_id != expected_session_id
            or runtime.writer_id
            not in {
                expected_writer_id,
                observation_writer_id(runtime.task_id, expected_session_id),
            }
        ):
            return True
        ended_lookup = getattr(getattr(self, "local", None), "codex_session_ended", None)
        if callable(ended_lookup):
            try:
                if await self._local(partial(ended_lookup, workspace, codex_session_id)):
                    return False
            except Exception:
                return False
        recorder = getattr(store, "record_workspace_session_route", None)
        if not callable(recorder):
            return True
        try:
            result = recorder(
                workspace=workspace,
                yoetz_session_id=runtime.session_id,
                yoetz_task_id=runtime.task_id,
                yoetz_writer_id=runtime.writer_id,
                codex_session_commitment=envelope.session_commitment,
                bound_at=timestamp_from_datetime(self.clock.now_utc()),
            )
        except Exception:
            return False
        return result is not False

    async def _renew_observed_activity(
        self,
        runtime: TaskRuntime,
        envelope: ObservationEnvelope,
        *,
        disposition: ObservationIngestDisposition,
        predecessor_session_id: str,
        predecessor_writer_id: str,
        route_bound: bool,
        workspace: str,
        codex_session_id: str,
    ) -> None:
        """Offer admitted native activity as contact evidence for its unchanged session.

        The evidence is the envelope's own receipt time, not the time this ingest delivered it:
        queued, swept, and retried rows routinely arrive after the session lease they prove, and
        judging them by delivery age discarded exactly the evidence a slow drain produces (#837).
        A duplicate delivery re-offers the same evidence; lineage applies it idempotently, so a
        retry whose first ingest committed before a later step failed can still count.
        ``Stop`` and ``SubagentStop`` prove the host was alive when they fired; only
        ``SessionEnd`` ends contact.  Future receipt times and evidence older than
        ``observed_activity_max_age_seconds`` are never offered.
        """

        hook = self.observed_activity_hook
        if (
            hook is None
            or not route_bound
            or disposition
            not in {ObservationIngestDisposition.ACCEPTED, ObservationIngestDisposition.DUPLICATE}
            or envelope.source
            not in {
                ObservationSource.CODEX_HOOK,
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CURSOR_HOOK,
            }
            or envelope.event_kind == "SessionEnd"
            or runtime.session_id != predecessor_session_id
            or runtime.writer_id
            not in {
                predecessor_writer_id,
                observation_writer_id(runtime.task_id, predecessor_session_id),
            }
        ):
            return
        ended_lookup = getattr(getattr(self, "local", None), "codex_session_ended", None)
        if callable(ended_lookup):
            try:
                if await self._local(partial(ended_lookup, workspace, codex_session_id)):
                    return
            except Exception:
                return
        observed_at = envelope.receipt_time.as_datetime()
        age = (self.clock.now_utc() - observed_at).total_seconds()
        if not 0 <= age <= self.observed_activity_max_age_seconds:
            return
        host_binding = getattr(self, "observed_host_session_binding", None)
        if host_binding is not None:
            await host_binding(
                runtime.task_id,
                predecessor_session_id,
                envelope.session_commitment,
            )
        await hook(runtime.task_id, predecessor_session_id, predecessor_writer_id, observed_at)

    async def _sweep_lineage(self, task_id: str) -> None:
        """Reconcile the task and its parent after observation materialization."""

        coordinator = self.lineage_coordinator
        if coordinator is None:
            return
        try:
            await coordinator.sweep_task(task_id)
            await coordinator.sweep_parent_of(task_id)
        except Exception as exc:
            # Lineage is an advisory/reconciliation sidecar. The observation ledger remains
            # authoritative, so preserve the accepted observation and expose the failed sweep
            # through the diagnostic stream for the next repair pass.
            record_unexpected_exception_without_raising(
                exc,
                component="application.observation_coordinator",
                operation="lineage_manifest_sweep_failed",
            )

    async def _bind_native_child_start(
        self,
        runtime: TaskRuntime,
        envelope: ObservationEnvelope,
        *,
        writer_routes: tuple[tuple[str, str], ...],
    ) -> str | None:
        """Join a native callback to its already admitted cooperative child route.

        Result IDs cannot select a task. Only the mapped runtime is consulted, and its catalog
        parent must match before any annotation is created. Recording the callback's native
        identity first also makes later SubagentStart/Stop delivery order independent.
        """

        fields = envelope.structural_payload
        if (
            envelope.source is not ObservationSource.CODEX_HOOK
            or envelope.event_kind != "PostToolUse"
            or "lineage_child_task_id" not in fields
        ):
            return None
        registry = self.host_lineage_registry
        coordinator = self.lineage_coordinator
        if registry is None or coordinator is None:
            return HostLineageRegistryReason.IDENTITY_CONFLICT.value
        child = fields.get("lineage_child_task_id")
        session = fields.get("lineage_child_session_id")
        writer = fields.get("lineage_child_writer_id")
        parent = fields.get("lineage_parent_task_id")
        admitted = set(writer_routes)
        if runtime.writer_id is not None:
            admitted.add((runtime.session_id, runtime.writer_id))
        if (
            child != runtime.task_id
            or type(session) is not str
            or type(writer) is not str
            or (session, writer) not in admitted
            or type(parent) is not str
            or not is_valid_id(IdKind.TASK, parent)
        ):
            return HostLineageRegistryReason.IDENTITY_CONFLICT.value
        lineage = await coordinator.catalog.task_lineage(runtime.task_id)
        if lineage is None or lineage.parent_task_id != parent:
            return HostLineageRegistryReason.IDENTITY_CONFLICT.value
        observation = _native_child_start_observation(envelope)
        if observation is None:
            return ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value
        # All task authority above comes from admitted mapping/catalog state; only the native
        # host correlation is supplied by the callback. The registry repeats parent ownership
        # validation when binding, and both writes are replayable after a partial failure.
        annotation = await registry.record_host_lineage_observation(
            parent,
            observation,
            observed_session_commitment=envelope.session_commitment,
            source=envelope.source,
        )
        await registry.bind_provisional_annotation(
            parent, annotation.correlation_id, runtime.task_id
        )
        return None

    async def _bind_child_session_start(
        self,
        runtime: TaskRuntime,
        envelope: ObservationEnvelope,
    ) -> tuple[bool, str | None]:
        """File a child rollout header's own start signal under its admitted parent task.

        Codex multi-agent v2 publishes the delegation in the child rollout's ``session_meta``
        header, which only the child's own session observes (issue #754). Filing it the ordinary
        way would name the child as its own parent, so the parent task comes from admitted
        catalog lineage — never from the host's ``parent_thread_id`` token, which cannot select a
        task. The first member says this envelope is handled here and must not also be recorded
        against the observing task.
        """

        fields = envelope.structural_payload
        if (
            envelope.source is not ObservationSource.CODEX_SESSION_STREAM
            or envelope.event_kind != "SubagentStart"
            or fields.get("stream_kind") != "session_meta"
        ):
            return False, None
        registry = self.host_lineage_registry
        coordinator = self.lineage_coordinator
        if registry is None or coordinator is None:
            return True, HostLineageRegistryReason.IDENTITY_CONFLICT.value
        observation = host_lineage_from_envelope(envelope)
        if observation is None:
            # The envelope already carries ``missing_subagent_identity``; noting it is the
            # caller's first step, so this stays a silent no-op rather than a second gap.
            return True, None
        lineage = await coordinator.catalog.task_lineage(runtime.task_id)
        parent = None if lineage is None else lineage.parent_task_id
        if parent is None:
            # The host says this thread is a delegated child, but no admitted lineage links it
            # to a parent task. Retain the bounded gap instead of inventing an attribution.
            return True, HostLineageRegistryReason.CHILD_NOT_FOUND.value
        annotation = await registry.record_host_lineage_observation(
            parent,
            observation,
            observed_session_commitment=envelope.session_commitment,
            source=envelope.source,
        )
        await registry.bind_provisional_annotation(
            parent, annotation.correlation_id, runtime.task_id
        )
        return True, None

    async def _record_host_lineage(
        self,
        runtime: TaskRuntime,
        workspace: str,
        envelope: ObservationEnvelope,
        *,
        writer_routes: tuple[tuple[str, str], ...] = (),
    ) -> None:
        """Persist one normalized host signal without promoting it to authorship."""

        missing_identity = ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value
        if missing_identity in envelope.gap_codes:
            await self._local(partial(self.local.note_coverage_gap, workspace, missing_identity))
        registry = self.host_lineage_registry
        if registry is None:
            return
        try:
            gap = await self._bind_native_child_start(
                runtime, envelope, writer_routes=writer_routes
            )
            if gap is not None:
                await self._local(partial(self.local.note_coverage_gap, workspace, gap))
            handled, child_gap = await self._bind_child_session_start(runtime, envelope)
            if child_gap is not None:
                await self._local(partial(self.local.note_coverage_gap, workspace, child_gap))
            if handled:
                return
            observation = host_lineage_from_envelope(envelope)
            if observation is None:
                return
            await registry.record_host_lineage_observation(
                runtime.task_id,
                observation,
                observed_session_commitment=envelope.session_commitment,
                source=envelope.source,
            )
        except HostLineageRegistryError as exc:
            if exc.reason in {
                HostLineageRegistryReason.ANNOTATION_AMBIGUOUS,
                HostLineageRegistryReason.IDENTITY_CONFLICT,
                HostLineageRegistryReason.BINDING_CONFLICT,
                HostLineageRegistryReason.CHILD_NOT_FOUND,
            }:
                # The event remains durable, but its host attribution is incomplete until a
                # stronger alias can disambiguate it.
                await self._local(
                    partial(self.local.note_coverage_gap, workspace, exc.reason.value)
                )
                return
            if exc.reason is HostLineageRegistryReason.STORAGE_CORRUPT:
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Host lineage storage is inconsistent.",
                    retryable=False,
                ) from exc
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "Host lineage storage is temporarily unavailable.",
                retryable=True,
            ) from exc

    async def _route_observation_runtime(
        self,
        task_id: str,
        session_id: str,
        *,
        required_capabilities: frozenset[RuntimeCapability] | None = None,
    ) -> TaskRuntime:
        capabilities = (
            frozenset(
                {
                    RuntimeCapability.STRUCTURAL_READ,
                    RuntimeCapability.PAYLOAD_READ,
                    RuntimeCapability.WRITE,
                }
            )
            if required_capabilities is None
            else required_capabilities
        )
        return await self.runtime.route(
            RouteCommand(
                session_id=session_id,
                writer_id=observation_writer_id(task_id, session_id),
                access=RouteAccess.WRITE,
                required_capabilities=capabilities,
            )
        )

    def _persist_successor_mapping(
        self, predecessor: LifecycleMapping, successor: LifecycleMapping
    ) -> None:
        """Cache a route only while its original lifecycle mapping is still current."""

        try:
            with acquire_session_lock(
                predecessor.codex_session_id, _state=self.state_root
            ) as owned:
                if not owned:
                    return
                latest = self.mapping_loader(predecessor.codex_session_id, _state=self.state_root)
                if latest != predecessor:
                    return
                self.mapping_storer(successor, _state=self.state_root)
        except Exception:
            return

    async def _route_observation_mapping(
        self,
        mapping: LifecycleMapping,
        *,
        required_capabilities: frozenset[RuntimeCapability] | None = None,
        route_history: list[LifecycleMapping] | None = None,
    ) -> tuple[TaskRuntime, LifecycleMapping]:
        """Route through the current session, following ``session_superseded`` (#577).

        ``route_history`` is an optional request-local trace of every admitted
        session binding visited while following a retirement chain.  The
        lifecycle mapping file is intentionally rewritten to the latest route,
        so callers that need to replay a session-bound operation must retain
        this bounded in-memory history before the predecessor is forgotten.
        """

        current = mapping
        seen = {mapping.yoetz_session_id}
        last_error: PublicOperationError | None = None
        if route_history is not None:
            route_history.append(current)
        for _ in range(_MAX_SUPERSEDED_ROUTE_HOPS):
            try:
                runtime = await self._route_observation_runtime(
                    current.yoetz_task_id,
                    current.yoetz_session_id,
                    required_capabilities=required_capabilities,
                )
            except PublicOperationError as error:
                last_error = error
                successor = _session_superseded_binding(
                    error, expected_task_id=current.yoetz_task_id
                )
                if successor is None:
                    raise
                session_id, writer_id = successor
                if session_id in seen:
                    raise
                seen.add(session_id)
                predecessor = current
                current = replace(
                    current,
                    yoetz_session_id=session_id,
                    yoetz_writer_id=writer_id,
                )
                if route_history is not None:
                    route_history.append(current)
                self._persist_successor_mapping(predecessor, current)
                continue
            return runtime, current
        if last_error is not None:
            raise last_error
        raise PublicOperationError(
            PublicErrorCode.SESSION_NOT_FOUND,
            "The requested task attachment was not found.",
            retryable=False,
        )

    async def _note_frontier_motion(
        self,
        runtime: TaskRuntime,
        workspace: str,
        codex_session_id: str,
        append_result: AppendResult,
    ) -> None:
        """Bind reconstructed append motion to the routed ledger's current lineage."""

        # A newly accepted append result is the routed head at its commit. A
        # completed-operation replay carries its historical result frontier,
        # so only that recovery path needs a fresh read to distinguish replay
        # from a same-task restore.
        lineage_frontier = append_result.result_frontier
        if append_result.outcome == "replayed":
            lineage_frontier = await runtime.ledger.load_frontier()
        await self._local(
            partial(
                self.local.note_frontier_motion,
                workspace,
                codex_session_id,
                from_sequence=append_result.subject_frontier.sequence,
                to_sequence=append_result.result_frontier.sequence,
                head_digest=append_result.result_frontier.head_digest,
                observation_record_count=len(append_result.accepted),
                task_id=runtime.task_id,
                lineage_frontier=lineage_frontier,
            )
        )

    async def _duplicate_agrees_with_ledger(
        self,
        runtime: TaskRuntime,
        envelope: ObservationEnvelope,
        batch: MaterializedObservationBatch,
    ) -> bool:
        """Whether a delivery whose events are all committed also states what the ledger holds.

        Event ids say it is the same call, not that it says the same thing. A Codex stream copy may
        differ from the committed result: the outcome correction then enriches an UNKNOWN or
        records the disagreement as a ``dedup_conflict`` correction, so nothing is lost. Any other
        source has no correction to carry a difference, so a copy stating an explicit outcome
        counts as a duplicate only when the committed result states exactly that outcome and exit
        status; anything else, or a projection that cannot confirm it, keeps the ledger's own
        refusal and its quarantine (fail closed, #560).
        """

        if envelope.source is ObservationSource.CODEX_SESSION_STREAM:
            return True
        stated = [
            item.draft.payload
            for item in batch.drafts
            if type(item.draft.payload) is ResultRecordedPayload
            and item.draft.payload.outcome is not ResultOutcome.UNKNOWN
        ]
        if not stated:
            return True
        projection = await runtime.ledger.load_projection(
            runtime.session_id, ProjectionView.CANDIDATE_FINDINGS
        )
        if (
            projection is None
            or type(projection.state) is not ProjectionState
            or projection.lag != 0
            or projection.rebuild_required
        ):
            return False
        for payload in stated:
            committed = projection.state.results.get(payload.result_id)
            if (
                committed is None
                or committed.payload is None
                or (committed.payload.outcome, committed.payload.exit_status)
                != (payload.outcome, payload.exit_status)
            ):
                return False
        return True

    async def _correct_recorded_outcome(
        self,
        runtime: TaskRuntime,
        workspace: str,
        store: TaskObservationPort,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        batch: MaterializedObservationBatch,
        *,
        resolved_mapping_version: str,
        append_result: AppendResult | None,
        already_committed: bool,
        legacy_session_id: str | None,
        legacy_writer_id: str | None,
        legacy_writer_routes: tuple[tuple[str, str], ...],
    ) -> None:
        """Apply a stream completion's explicit outcome to the call's recorded UNKNOWN one.

        Runs when the completion's own batch was already recorded: as a replay of the
        committed operation, or (#1027) because every event of the batch is already in the
        ledger under another delivery shape. A freshly appended batch carries its explicit
        outcome itself. Historical action/result rows are never rewritten: the correction is a
        second, source-independent result linked to the same action, so retries are idempotent.
        """

        correction = materialize_observation_outcome_correction(
            envelope,
            task_id=runtime.task_id,
        )
        if correction.skip_reason is not None or not correction.drafts:
            return
        if not already_committed and (append_result is None or append_result.outcome != "replayed"):
            return
        projection = await runtime.ledger.load_projection(
            runtime.session_id,
            ProjectionView.CANDIDATE_FINDINGS,
        )
        if (
            projection is None
            or type(projection.state) is not ProjectionState
            or projection.lag != 0
            or projection.rebuild_required
        ):
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "Observation outcome projection is unavailable.",
                retryable=True,
            )
        if resolved_mapping_version == MATERIALIZATION_MAPPING_VERSION:
            core_result = next(
                (
                    item.draft.payload
                    for item in batch.drafts
                    if type(item.draft.payload) is ResultRecordedPayload
                ),
                None,
            )
            if type(core_result) is not ResultRecordedPayload:
                if already_committed:
                    # A duplicate whose batch carries no result of its own has no recorded
                    # outcome to enrich; it must not hold the drain on a retry.
                    return
                raise PublicOperationError(
                    PublicErrorCode.SERVICE_UNAVAILABLE,
                    "Observation outcome projection is unavailable.",
                    retryable=True,
                )
            core_result_id = core_result.result_id
            existing_result = projection.state.results.get(core_result_id)
        else:
            # A replayed legacy-mapping operation committed
            # its graph under pre-upgrade record identities
            # that cannot be re-derived here, and it may be a
            # legacy hook operation whose result is UNKNOWN.
            # Its accepted event ids are the exact link to
            # the committed result, so consult that result
            # before deciding whether the explicit stream
            # outcome still needs a correction (#418).
            if append_result is None:
                raise PublicOperationError(
                    PublicErrorCode.SERVICE_UNAVAILABLE,
                    "Observation outcome projection is unavailable.",
                    retryable=True,
                )
            accepted_event_ids = {item.event_id for item in append_result.accepted}
            committed_results = [
                (candidate_id, record)
                for candidate_id, record in (projection.state.results.items())
                if record.source_event_id in accepted_event_ids
            ]
            if len(committed_results) != 1:
                raise PublicOperationError(
                    PublicErrorCode.SERVICE_UNAVAILABLE,
                    "Observation outcome projection is unavailable.",
                    retryable=True,
                )
            core_result_id, existing_result = committed_results[0]
        if existing_result is None or existing_result.payload is None:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "Observation outcome projection is unavailable.",
                retryable=True,
            )
        existing_payload = existing_result.payload
        correction_payload = correction.drafts[0].draft.payload
        if type(correction_payload) is not ResultRecordedPayload:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "Observation outcome correction is unavailable.",
                retryable=True,
            )
        incoming_fact = (
            correction_payload.outcome,
            correction_payload.exit_status,
        )
        existing_fact = (
            existing_payload.outcome,
            existing_payload.exit_status,
        )
        prior_corrections = tuple(
            record.payload
            for result_id, record in projection.state.results.items()
            if result_id != core_result_id
            and record.payload is not None
            and record.payload.action_id == existing_payload.action_id
        )
        conflict = (
            existing_payload.outcome is not ResultOutcome.UNKNOWN and existing_fact != incoming_fact
        ) or any((item.outcome, item.exit_status) != incoming_fact for item in prior_corrections)
        should_correct = (
            existing_payload.outcome is ResultOutcome.UNKNOWN or existing_fact != incoming_fact
        )
        if should_correct:
            if resolved_mapping_version != MATERIALIZATION_MAPPING_VERSION:
                # Bind the correction to the exact committed
                # legacy action (and its committed event as
                # causal parent when the projection still
                # exposes it) instead of the current
                # canonical action identities.
                action_record = projection.state.actions.get(existing_payload.action_id)
                correction = materialize_observation_outcome_correction(
                    envelope,
                    task_id=runtime.task_id,
                    conflict=conflict,
                    target_action_id=existing_payload.action_id,
                    target_action_event_id=(
                        action_record.source_event_id if action_record is not None else None
                    ),
                )
            elif conflict:
                correction = materialize_observation_outcome_correction(
                    envelope,
                    task_id=runtime.task_id,
                    conflict=True,
                )
            corrected = await self._append_materialized(
                runtime,
                envelope,
                correction,
                legacy_session_id=legacy_session_id,
                legacy_writer_id=legacy_writer_id,
                legacy_writer_routes=legacy_writer_routes,
            )
            if corrected is not None and not isinstance(corrected, _AlreadyCommitted):
                (
                    correction_operation_id,
                    correction_digest,
                    correction_result,
                    correction_mapping_version,
                    correction_draft_roles,
                ) = corrected
                store.record_logical_identity_claim(
                    workspace=workspace,
                    logical_identity=observation_claim_identity(
                        envelope,
                        correction_draft_roles,
                        mapping_version=correction_mapping_version,
                    ),
                    materialization_digest=correction_digest,
                    operation_id=correction_operation_id,
                    source_mask=2,
                    mapping_version=correction_mapping_version,
                    materialized_at=timestamp_from_datetime(self.clock.now_utc()),
                )
                if correction_result is not None:
                    await self._note_frontier_motion(
                        runtime,
                        workspace,
                        codex_session_id,
                        correction_result,
                    )

    async def _align_codex_stream_generation(
        self,
        runtime: TaskRuntime,
        workspace: str,
        envelope: ObservationEnvelope,
    ) -> ObservationEnvelope:
        """Bind a post-compaction stream completion to its hook call's generation (#1019).

        The hook generation advances at every Codex ``SessionStart`` (including the
        ``compact`` start); the stream generation follows the rollout file. After a
        compaction the two differ, so the completion would mint a second command action
        beside the hook call's UNKNOWN one. Rebind only when every guard holds: the same
        task ledger (the ids are task-scoped), the same workspace lane and host session,
        the same host call id, exactly one other-generation hook action in this task, the
        same keyed command identity on that action, and no explicit outcome on it except
        one this completion itself recorded (an idempotent retry). Anything else keeps the
        stream's own generation, which is the pre-fix behavior.

        The binding belongs to the whole ingest, so it is resolved before the completion's
        captured-content manifests are looked up (#1027): those are keyed by the call's
        generation-qualified identity, and the hook post's committed role set includes the
        captured-evidence roles they reconstruct. Resolved after the lookup, the completion
        reconstructed a contentless role set, missed the hook post's committed operation and
        was refused by the ledger for reusing its result event id.
        """

        own_generation = envelope.cursor.source_generation
        own = codex_stream_call_generation_links(
            envelope, task_id=runtime.task_id, generations=(own_generation,)
        )
        if len(own) != 1:
            return envelope
        ledger = getattr(runtime, "ledger", None)
        current = getattr(self.local, "current_session_generation", None)
        if not callable(getattr(ledger, "projected_action_event", None)) or not callable(current):
            return envelope
        if await action_event_committed(ledger, own[0].action_id, own[0].action_event_id):
            return envelope
        hook_generation = await self._local(
            partial(
                cast(Callable[[str, str], int], current),
                workspace,
                envelope.session_commitment,
            )
        )
        if type(hook_generation) is not int or isinstance(hook_generation, bool):
            return envelope
        top = max(hook_generation, own_generation)
        candidates = tuple(
            generation
            for generation in range(top, max(0, top - _CODEX_GENERATION_ALIAS_WINDOW), -1)
            if generation != own_generation
        )
        matches = [
            link
            for link in codex_stream_call_generation_links(
                envelope, task_id=runtime.task_id, generations=candidates
            )
            if await action_event_committed(ledger, link.action_id, link.action_event_id)
        ]
        if len(matches) != 1:
            return envelope
        match = matches[0]
        projection = await runtime.ledger.load_projection(
            runtime.session_id, ProjectionView.CANDIDATE_FINDINGS
        )
        if (
            projection is None
            or type(projection.state) is not ProjectionState
            or projection.lag != 0
            or projection.rebuild_required
        ):
            return envelope
        action_record = projection.state.actions.get(action_id(match.action_id))
        action_payload = action_record.payload if action_record is not None else None
        if (
            action_payload is None
            or action_payload.action_kind is not ActionKind.COMMAND
            or action_payload.command is None
            or action_payload.command.split(" ", 1)[0] != match.command_identity
        ):
            return envelope
        aligned = replace(
            envelope, cursor=replace(envelope.cursor, source_generation=match.generation)
        )
        # Results this completion itself mints under the aligned identity: its core result
        # (when it lands before the hook's post) and its outcome correction. A retry finds
        # them already recorded; any other explicit outcome on the hook call fails closed.
        own_results = {
            str(item.draft.payload.result_id)
            for item in materialize_observation_envelope(aligned, task_id=runtime.task_id).drafts
            if type(item.draft.payload) is ResultRecordedPayload
        } | {
            str(item.draft.payload.result_id)
            for item in materialize_observation_outcome_correction(
                aligned, task_id=runtime.task_id
            ).drafts
            if type(item.draft.payload) is ResultRecordedPayload
        }
        for result_key, record in projection.state.results.items():
            payload = record.payload
            if (
                payload is not None
                and str(payload.action_id) == match.action_id
                and payload.outcome is not ResultOutcome.UNKNOWN
                and str(result_key) not in own_results
            ):
                return envelope
        return aligned

    async def _plan_action_link(
        self,
        runtime: TaskRuntime,
        *,
        envelope: ObservationEnvelope,
        batch: MaterializedObservationBatch,
        replay_role_sets: tuple[tuple[str, ...], ...],
    ) -> _ActionLinkPlan:
        """Choose which phase of one paired host call records its single action (#917).

        The plan carries the batch to append (``skip`` when nothing is left) and
        every role set either committed shape of this phase could hold, so the
        append step still finds a replay of its own operation first. The action
        draft is dropped only when the task ledger already projects this exact
        action event; otherwise the full batch is appended, as the pre-#917
        mapping did for the same phase.
        """

        link = paired_action_link(envelope, batch, task_id=runtime.task_id)
        if link is None:
            return _ActionLinkPlan(None, batch, False, ())
        own_role_sets = tuple(
            dict.fromkeys((tuple(item.role for item in batch.drafts), *replay_role_sets))
        )
        linked_role_sets = tuple(
            dict.fromkeys(
                linked
                for roles in own_role_sets
                if PAIRED_ACTION_ROLE in roles and (linked := paired_action_linked_roles(roles))
            )
        )
        variants = tuple(dict.fromkeys((*own_role_sets, *linked_role_sets)))
        # Test doubles and older in-process ledgers may lack the read seam; without
        # it the action cannot be proven to exist, so this phase records it.
        ledger = getattr(runtime, "ledger", None)
        if not callable(getattr(ledger, "projected_action_event", None)):
            return _ActionLinkPlan(link, batch, False, variants)
        if not await action_event_committed(ledger, link.action_id, link.action_event_id):
            return _ActionLinkPlan(link, batch, False, variants)
        return _ActionLinkPlan(link, link.linked, not link.linked.drafts, variants)

    async def _append_materialized(
        self,
        runtime: TaskRuntime,
        envelope: ObservationEnvelope,
        batch: MaterializedObservationBatch,
        *,
        captured_content: tuple[ObservationContentManifest, ...] = (),
        legacy_session_id: str | None = None,
        legacy_writer_id: str | None = None,
        legacy_writer_routes: tuple[tuple[str, str], ...] = (),
        replay_required: bool = False,
        replay_claims: tuple[tuple[ObservationLogicalIdentityClaim, tuple[str, ...]], ...] = (),
        replay_draft_role_sets: tuple[tuple[str, ...], ...] = (),
    ) -> tuple[str, str, AppendResult | None, str, tuple[str, ...]] | _AlreadyCommitted | None:
        writer_id = runtime.writer_id
        if writer_id is None:
            return None
        logical_identity = canonical_logical_identity(envelope)
        draft_roles = tuple(item.role for item in batch.drafts)
        candidate_role_sets = tuple(dict.fromkeys((draft_roles, *replay_draft_role_sets)))
        writer_routes = [(runtime.session_id, writer_id)]
        for route in legacy_writer_routes:
            if route not in writer_routes:
                writer_routes.append(route)
        if legacy_writer_id is not None and legacy_writer_id != writer_id:
            route = (legacy_session_id or runtime.session_id, legacy_writer_id)
            if route not in writer_routes:
                writer_routes.append(route)
        lineage = host_lineage_from_envelope(envelope)
        stronger_subagent_identity = (
            lineage is not None and lineage.correlation.parent_tool_call_id is not None
        )
        for (claim_digest, claim_operation_id, claim_mapping_version), claim_roles in replay_claims:
            if stronger_subagent_identity and claim_mapping_version == "obs-ledger/1.6.0":
                # That historical mapping omitted the parent call. Its operation cannot
                # prove this stronger event belongs to the same invocation.
                continue
            if self._stable_operation_id(claim_digest) != claim_operation_id:
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Observation logical identity claim is invalid.",
                    retryable=False,
                )
            existing = await runtime.ledger.lookup_task_operation(writer_id, claim_operation_id)
            if existing is None:
                continue
            if (
                getattr(existing, "operation_id", claim_operation_id) != claim_operation_id
                or existing.request_digest != claim_digest
            ):
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Observation logical identity claim does not match its operation.",
                    retryable=False,
                )
            return (
                claim_operation_id,
                claim_digest,
                _append_result_from_committed(existing),
                claim_mapping_version,
                claim_roles,
            )
        # Check the stable operation identity before staging payloads. A replay
        # after "ledger committed, local outbox not acknowledged" must not
        # create orphan encrypted objects on every retry.
        #
        # The current mapping's operation digest is task-scoped, matching the
        # stable event ids it commits, so the committed operation is resolved
        # task-wide: a workflow reattach in the same host session rotates the
        # routed Yoetz session and observation writer, and the repeat must
        # still find the operation the predecessor session committed instead
        # of reminting its event ids into a ledger that already holds them
        # (#560). A hit whose request digest differs is a genuine conflicting
        # reuse of the operation identity and fails closed.
        for candidate_roles in candidate_role_sets:
            candidate_digest = observation_operation_digest(
                task_id=runtime.task_id,
                logical_identity=logical_identity,
                draft_roles=candidate_roles,
                mapping_version=MATERIALIZATION_MAPPING_VERSION,
            )
            candidate_operation_id = self._stable_operation_id(candidate_digest)
            existing = await runtime.ledger.lookup_task_operation(writer_id, candidate_operation_id)
            if existing is None:
                continue
            if existing.request_digest != candidate_digest:
                raise PublicOperationError(
                    PublicErrorCode.IDEMPOTENCY_CONFLICT,
                    "Observation operation identity is already committed with other content.",
                    retryable=False,
                )
            return (
                candidate_operation_id,
                candidate_digest,
                _append_result_from_committed(existing),
                MATERIALIZATION_MAPPING_VERSION,
                candidate_roles,
            )
        # Legacy mapping versions bound the digest to the routed session and
        # writer (1.2-1.4).  Mapping 1.5 was task-scoped but used the older
        # identity shape; search it through the same task-wide lookup with the
        # legacy identity before staging so pre-1.6 rows remain replayable.
        for mapping_version in MATERIALIZATION_LEGACY_MAPPING_VERSIONS:
            if stronger_subagent_identity and mapping_version == "obs-ledger/1.6.0":
                continue
            legacy_identities = (
                logical_identity,
                canonical_logical_identity(envelope, mapping_version=mapping_version),
            )
            # Preserve the established writer/role lookup order for the
            # session-bound mappings. Try every role under the current
            # identity before falling back to the historical identity; this
            # keeps replay probes deterministic while still finding rows
            # written before the source/session identity was widened.
            for legacy_identity in dict.fromkeys(legacy_identities):
                candidate_writer_routes = (
                    writer_routes
                    if mapping_version in SESSION_BOUND_MAPPING_VERSIONS
                    else ((runtime.session_id, writer_id),)
                )
                for candidate_session_id, candidate_writer_id in candidate_writer_routes:
                    for candidate_roles in candidate_role_sets:
                        digest_kwargs: dict[str, str] = {}
                        if mapping_version in SESSION_BOUND_MAPPING_VERSIONS:
                            digest_kwargs = {
                                "session_id": candidate_session_id,
                                "writer_id": candidate_writer_id,
                            }
                        candidate_digest = observation_operation_digest(
                            task_id=runtime.task_id,
                            logical_identity=legacy_identity,
                            draft_roles=candidate_roles,
                            mapping_version=mapping_version,
                            **digest_kwargs,
                        )
                        candidate_operation_id = self._stable_operation_id(candidate_digest)
                        existing = (
                            await runtime.ledger.lookup_operation(
                                candidate_writer_id, candidate_operation_id
                            )
                            if mapping_version in SESSION_BOUND_MAPPING_VERSIONS
                            else await runtime.ledger.lookup_task_operation(
                                writer_id, candidate_operation_id
                            )
                        )
                        if existing is not None:
                            if existing.request_digest != candidate_digest:
                                raise PublicOperationError(
                                    PublicErrorCode.IDEMPOTENCY_CONFLICT,
                                    "Observation operation identity is already committed with other content.",
                                    retryable=False,
                                )
                            return (
                                candidate_operation_id,
                                candidate_digest,
                                _append_result_from_committed(existing),
                                mapping_version,
                                candidate_roles,
                            )

        # No operation was found under any role-set shape this delivery can reconstruct. A
        # call-keyed delivery's event ids derive from the task, the call and the role, not from
        # the delivery's shape, so a batch whose every event the ledger already holds is a
        # duplicate of an earlier delivery of the same call (a hook copy and a stream copy, or a
        # content-bearing and a contentless copy). Appending it would only be refused as
        # EVENT_INVALID and quarantined as a content refusal, losing the explicit outcome a
        # stream copy carries (#1027). An id derived from a source identity alone can be reused
        # by another call, so that collision stays a conflict and fails closed (#560).
        draft_event_ids = tuple(str(item.draft.event_id) for item in batch.drafts)
        duplicate_by_events = observation_event_ids_call_keyed(envelope)
        if (
            duplicate_by_events
            and await observation_already_committed(runtime.ledger, draft_event_ids)
            and await self._duplicate_agrees_with_ledger(runtime, envelope, batch)
        ):
            return _AlreadyCommitted(frozenset(draft_event_ids))

        if replay_required:
            raise PublicOperationError(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The retained observation replay route is incomplete.",
                retryable=False,
                safe_details={
                    "reason_code": "session_superseded",
                    "task_id": runtime.task_id,
                    "session_id": runtime.session_id,
                    "writer_id": writer_id,
                },
            )

        digest = observation_operation_digest(
            task_id=runtime.task_id,
            logical_identity=logical_identity,
            draft_roles=draft_roles,
            mapping_version=MATERIALIZATION_MAPPING_VERSION,
        )
        operation_id = self._stable_operation_id(digest)

        artifact_ids = {str(ref) for item in batch.drafts for ref in item.draft.artifact_refs}
        artifact_object_refs: list[ObjectRef] = []
        for manifest in captured_content:
            if manifest.object_id not in artifact_ids:
                continue
            if manifest.envelope_digest is None:
                raise ValueError("captured_object_unavailable")
            ref = await runtime.objects.resolve_verified(
                manifest.object_id, manifest.envelope_digest
            )
            if (
                ref.metadata.task_id != runtime.task_id
                or ref.metadata.kind is not ObjectKind.CAPTURED_CONTENT
                or ref.metadata.media_type != _CAPTURED_CONTENT_MEDIA_TYPE
            ):
                raise ValueError("captured_object_invalid")
            artifact_object_refs.append(ref)
        if {ref.object_id for ref in artifact_object_refs} != artifact_ids:
            raise ValueError("captured_object_unavailable")
        artifact_object_refs_tuple = tuple(
            sorted(artifact_object_refs, key=lambda ref: ref.object_id.encode("ascii"))
        )

        author = observation_author()
        refs: list[ObjectRef] = []
        entries: list[AppendEntry] = []
        staged_objects: list[StagedObject] = []
        try:
            for item in batch.drafts:
                commitment = await runtime.objects.commitment_for(
                    item.payload_bytes, ObjectKind.EVENT_PAYLOAD
                )
                metadata = ObjectMetadata(
                    ObjectKind.EVENT_PAYLOAD,
                    media_type_for_schema(item.draft.schema.name),
                    runtime.task_id,
                    self.clock.now_utc(),
                )
                staged = await runtime.objects.stage(
                    ObjectSource(data=item.payload_bytes, declared_size=len(item.payload_bytes)),
                    metadata,
                )
                staged_objects.append(staged)
                if staged.commitment != commitment:
                    raise PublicOperationError(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Observation payload commitment mismatch.",
                        retryable=False,
                    )
                ref = await runtime.objects.finalize(staged)
                refs.append(ref)
                entries.append(
                    AppendEntry(
                        item.draft,
                        author,
                        ref,
                        commitment,
                        metadata.media_type,
                        ref.plaintext_size,
                        batch.channel,
                        batch.coverage,
                        item.projection_status,
                    )
                )
            command = AppendCommand(
                runtime.task_id,
                runtime.session_id,
                writer_id,
                operation_id,
                OperationKind.PUBLISH_WORK,
                digest,
                None,
                tuple(entries),
                artifact_object_refs=artifact_object_refs_tuple,
            )
            mutation = PreparedMutation(
                command.writer_id,
                command.operation_id,
                command.request_digest,
                command.expected_frontier,
                tuple(refs),
                command,
            )
        except BaseException:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise
        try:
            append_result = await run_prepared_append(runtime.ledger, mutation)
        except PreSubmissionCancelled:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise
        except PublicOperationError as exc:
            # The ledger refused the batch for an event id it already holds. If every event of
            # the batch is committed (a delivery that committed between the check above and this
            # append), that refusal classifies the batch as a duplicate, never a content refusal
            # to quarantine (#1027). Any other refusal, including a partial overlap, stands.
            if (
                not duplicate_by_events
                or exc.code is not PublicErrorCode.EVENT_INVALID
                or not await observation_already_committed(runtime.ledger, draft_event_ids)
                or not await self._duplicate_agrees_with_ledger(runtime, envelope, batch)
            ):
                raise
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            return _AlreadyCommitted(frozenset(draft_event_ids))
        return (
            operation_id,
            digest,
            append_result,
            MATERIALIZATION_MAPPING_VERSION,
            draft_roles,
        )

    async def _append_inspection_snapshot(
        self,
        runtime: TaskRuntime,
        snapshot: ObservationInspectionSnapshot,
    ) -> AppendResult | None:
        """Append one idempotent harness-owned inspection evidence batch."""

        writer_id = runtime.writer_id
        if writer_id is None:
            return None
        batch = materialize_observation_inspection_snapshot(snapshot, task_id=runtime.task_id)
        if batch.skip_reason is not None or not batch.drafts:
            return None
        operation_digest = canonical_digest(
            JsonObject(
                {
                    "format": "yoetz.observation-inspection-ledger-materialization/1",
                    "snapshot_id": snapshot.snapshot_id,
                    "subject_state_digest": snapshot.subject_state_digest,
                    "changed_paths_digest": snapshot.changed_paths_digest,
                    "facts_object_id": snapshot.facts_object_id,
                    "facts_content_digest": snapshot.facts_content_digest,
                    "excerpt_object_id": snapshot.excerpt_object_id,
                    "excerpt_content_digest": snapshot.excerpt_content_digest,
                    "task_id": runtime.task_id,
                    "session_id": runtime.session_id,
                    "writer_id": writer_id,
                }
            )
        )
        operation_id = self._stable_operation_id(operation_digest)
        existing = await runtime.ledger.lookup_operation(writer_id, operation_id)
        if existing is not None:
            return _append_result_from_committed(existing)

        return await self._append_structural_batch(runtime, batch, operation_digest)

    async def _append_structural_batch(
        self, runtime: TaskRuntime, batch: MaterializedObservationBatch, operation_digest: str
    ) -> AppendResult | None:
        writer_id = runtime.writer_id
        if writer_id is None:
            return None
        operation_id = self._stable_operation_id(operation_digest)
        existing = await runtime.ledger.lookup_task_operation(writer_id, operation_id)
        if existing is not None:
            if existing.request_digest != operation_digest:
                raise ValueError("observation_operation_conflict")
            return _append_result_from_committed(existing)

        author = observation_author()
        refs: list[ObjectRef] = []
        entries: list[AppendEntry] = []
        staged_objects: list[StagedObject] = []
        try:
            for item in batch.drafts:
                commitment = await runtime.objects.commitment_for(
                    item.payload_bytes, ObjectKind.EVENT_PAYLOAD
                )
                metadata = ObjectMetadata(
                    ObjectKind.EVENT_PAYLOAD,
                    media_type_for_schema(item.draft.schema.name),
                    runtime.task_id,
                    self.clock.now_utc(),
                )
                staged = await runtime.objects.stage(
                    ObjectSource(data=item.payload_bytes, declared_size=len(item.payload_bytes)),
                    metadata,
                )
                staged_objects.append(staged)
                if staged.commitment != commitment:
                    raise PublicOperationError(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Observation inspection payload commitment mismatch.",
                        retryable=False,
                    )
                ref = await runtime.objects.finalize(staged)
                refs.append(ref)
                entries.append(
                    AppendEntry(
                        item.draft,
                        author,
                        ref,
                        commitment,
                        metadata.media_type,
                        ref.plaintext_size,
                        batch.channel,
                        batch.coverage,
                        item.projection_status,
                    )
                )
            command = AppendCommand(
                runtime.task_id,
                runtime.session_id,
                writer_id,
                operation_id,
                OperationKind.PUBLISH_WORK,
                operation_digest,
                None,
                tuple(entries),
            )
            mutation = PreparedMutation(
                command.writer_id,
                command.operation_id,
                command.request_digest,
                command.expected_frontier,
                tuple(refs),
                command,
            )
        except BaseException:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise
        try:
            return await run_prepared_append(runtime.ledger, mutation)
        except PreSubmissionCancelled:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise

    async def _materialize_approved_check(
        self,
        runtime: TaskRuntime,
        completed: CompletedApprovedCheck,
        *,
        legacy_session_id: str | None = None,
        legacy_writer_id: str | None = None,
    ) -> None:
        """Append one idempotent service-owned action/evidence/result graph."""

        writer_id = runtime.writer_id
        if writer_id is None:
            return
        result = completed.result
        operation_digest = canonical_digest(
            JsonObject(
                {
                    "format": "yoetz.approved-check-ledger-materialization/1",
                    "job_id": completed.job.job_id,
                    "approval_commitment": completed.job.approval_commitment,
                    "result_digest": result.result_digest,
                    "task_id": runtime.task_id,
                    "session_id": runtime.session_id,
                    "writer_id": writer_id,
                }
            )
        )
        operation_id = self._stable_operation_id(operation_digest)
        if await runtime.ledger.lookup_operation(writer_id, operation_id) is not None:
            return
        if legacy_writer_id is not None and legacy_writer_id != writer_id:
            legacy_digest = canonical_digest(
                JsonObject(
                    {
                        "format": "yoetz.approved-check-ledger-materialization/1",
                        "job_id": completed.job.job_id,
                        "approval_commitment": completed.job.approval_commitment,
                        "result_digest": result.result_digest,
                        "task_id": runtime.task_id,
                        "session_id": legacy_session_id or runtime.session_id,
                        "writer_id": legacy_writer_id,
                    }
                )
            )
            legacy_operation_id = self._stable_operation_id(legacy_digest)
            if (
                await runtime.ledger.lookup_operation(legacy_writer_id, legacy_operation_id)
                is not None
            ):
                return

        receipt_document = JsonObject(
            {
                "format": "yoetz.approved-check-evidence/1",
                "job_id": completed.job.job_id,
                "approval_id": completed.approval_id,
                "approval_commitment": completed.job.approval_commitment,
                "result_digest": result.result_digest,
                "status": result.status.value,
                "outcome": result.outcome.value,
                "exit_status": result.exit_status,
                "output_digest": result.output_digest,
                "output_bytes": result.output_bytes,
                "output_object_id": completed.output_object_id,
                "subject_state_before": completed.job.subject_state_digest,
                "subject_state_after": completed.subject_state_after,
                "is_current": completed.is_current,
                "recorded_at": completed.recorded_at,
            }
        )
        receipt_bytes = canonical_encode(receipt_document)
        receipt_metadata = ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "application/vnd.yoetz.approved-check-evidence+json",
            runtime.task_id,
            self.clock.now_utc(),
        )
        staged_objects: list[StagedObject] = []
        try:
            staged_receipt = await runtime.objects.stage(
                ObjectSource(data=receipt_bytes, declared_size=len(receipt_bytes)), receipt_metadata
            )
            staged_objects.append(staged_receipt)
            receipt_ref = await runtime.objects.finalize(staged_receipt)
            receipt_digest = canonical_digest(receipt_document)

            source_identity = f"approved-check:{completed.job.job_id}:{result.result_digest}"
            mapping = "approved-check/1.0.0"
            action_value = action_id(
                stable_observation_id(
                    kind=IdKind.ACTION,
                    task_id=runtime.task_id,
                    source_identity=source_identity,
                    mapping_version=mapping,
                    role="action",
                )
            )
            evidence_value = evidence_id(
                stable_observation_id(
                    kind=IdKind.EVIDENCE,
                    task_id=runtime.task_id,
                    source_identity=source_identity,
                    mapping_version=mapping,
                    role="evidence",
                )
            )
            result_value = result_id(
                stable_observation_id(
                    kind=IdKind.RESULT,
                    task_id=runtime.task_id,
                    source_identity=source_identity,
                    mapping_version=mapping,
                    role="result",
                )
            )
            action_event = event_id(
                stable_observation_id(
                    kind=IdKind.EVENT,
                    task_id=runtime.task_id,
                    source_identity=source_identity,
                    mapping_version=mapping,
                    role="action_event",
                )
            )
            evidence_event = event_id(
                stable_observation_id(
                    kind=IdKind.EVENT,
                    task_id=runtime.task_id,
                    source_identity=source_identity,
                    mapping_version=mapping,
                    role="evidence_event",
                )
            )
            result_event = event_id(
                stable_observation_id(
                    kind=IdKind.EVENT,
                    task_id=runtime.task_id,
                    source_identity=source_identity,
                    mapping_version=mapping,
                    role="result_event",
                )
            )
            occurred_at = timestamp_from_string(completed.recorded_at)
            subject_state = SubjectStateRef(
                described_state=f"approved-check:{completed.job.subject_state_digest}"
            )
            evidence_payload = EvidenceRecordedPayload(
                evidence_id=evidence_value,
                evidence_kind=EvidenceKind.TEST_RESULT,
                strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
                observed_at=occurred_at,
                captured_object_id=object_id(receipt_ref.object_id),
                content_digest=receipt_digest,
                description=f"Approved check result status={result.status.value}",
                subject_state=subject_state,
                digest_binding=EvidenceDigestBinding(
                    subject=EvidenceDigestSubject.APPROVED_CHECK_RECEIPT,
                    content_availability=EvidenceContentAvailability.CAPTURED,
                    byte_count=len(receipt_bytes),
                    provenance=EvidenceDigestProvenance.APPROVED_CHECK,
                    approval_commitment=completed.job.approval_commitment,
                    approved_check_result_digest=result.result_digest,
                ),
            )
            drafts = (
                EventDraft(
                    action_event,
                    EventSchema("action_recorded", "1.0.0"),
                    occurred_at,
                    (),
                    ActionRecordedPayload(
                        action_id=action_value,
                        action_kind=ActionKind.COMMAND,
                        description=f"Ran approved check {completed.approval_id}",
                        command="approved-check-service",
                        subject_state=subject_state,
                    ),
                    (),
                    (),
                ),
                EventDraft(
                    evidence_event,
                    EventSchema("evidence_recorded", EVIDENCE_TYPED_SCHEMA_VERSION),
                    occurred_at,
                    (action_event,),
                    evidence_payload,
                    (object_id(receipt_ref.object_id),),
                    (),
                ),
                EventDraft(
                    result_event,
                    EventSchema("result_recorded", "1.0.0"),
                    occurred_at,
                    tuple(sorted((action_event, evidence_event), key=str.encode)),
                    ResultRecordedPayload(
                        result_id=result_value,
                        action_id=action_value,
                        outcome=(
                            ResultOutcome.SUCCESS
                            if result.status is ApprovedCheckStatus.PASSED
                            else ResultOutcome.FAILURE
                        ),
                        exit_status=result.exit_status,
                        summary=f"Approved check status={result.status.value}",
                        subject_state=subject_state,
                        evidence_refs=(evidence_value,),
                    ),
                    (),
                    (evidence_value,),
                ),
            )
            coverage = replace(
                coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
                evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
            )
            refs: list[ObjectRef] = [receipt_ref]
            entries: list[AppendEntry] = []
            for draft in drafts:
                payload_bytes = canonical_encode(encode_payload(cast(Any, draft.payload)))
                metadata = ObjectMetadata(
                    ObjectKind.EVENT_PAYLOAD,
                    media_type_for(draft.schema.name),
                    runtime.task_id,
                    self.clock.now_utc(),
                )
                staged = await runtime.objects.stage(
                    ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)), metadata
                )
                staged_objects.append(staged)
                payload_ref = await runtime.objects.finalize(staged)
                refs.append(payload_ref)
                entries.append(
                    AppendEntry(
                        draft,
                        approved_check_author(),
                        payload_ref,
                        payload_ref.commitment,
                        metadata.media_type,
                        payload_ref.plaintext_size,
                        PublicationChannel.ENGINE_DERIVED,
                        coverage,
                        "projected",
                    )
                )
            command = AppendCommand(
                runtime.task_id,
                runtime.session_id,
                writer_id,
                operation_id,
                OperationKind.PUBLISH_WORK,
                operation_digest,
                None,
                tuple(entries),
                artifact_object_refs=(receipt_ref,),
            )
            mutation = PreparedMutation(
                command.writer_id,
                command.operation_id,
                command.request_digest,
                command.expected_frontier,
                tuple(refs),
                command,
            )
        except BaseException:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise
        try:
            await run_prepared_append(runtime.ledger, mutation)
        except PreSubmissionCancelled:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise

    async def _capture_content(
        self,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        *,
        workspace: str,
        envelope: ObservationEnvelope,
        chunks: tuple[ObservationContentChunk, ...],
        capture_fence: Callable[[], Awaitable[bool]] | None = None,
        expected_capture_parts: tuple[ObservationCapturePart, ...] | None = None,
        allow_incomplete_recovery: bool = False,
        source_qualified_capture: bool = False,
    ) -> tuple[
        tuple[ObservationContentManifest, ...],
        tuple[tuple[ObservationContentManifest, ...], ...],
        bool,
        bool,
    ]:
        """Assemble usable content and replay-only manifest candidates.

        Authenticated, readable objects may strengthen the new materialization.
        Stored manifest identities also reconstruct prior operation role sets,
        but an unreadable object is replay-only and never grants captured
        coverage to a new append.
        """

        self._capture_budget_exhausted = False
        logical_identity = canonical_logical_identity(envelope)
        content_identity = observation_content_identity(envelope)
        legacy_logical_identities = tuple(
            canonical_logical_identity(envelope, mapping_version=mapping_version)
            for mapping_version in MATERIALIZATION_LEGACY_MAPPING_VERSIONS
        )
        legacy_content_identities = tuple(
            observation_content_identity(envelope, mapping_version=mapping_version)
            for mapping_version in MATERIALIZATION_LEGACY_MAPPING_VERSIONS
        )
        manifests: dict[str, ObservationContentManifest] = {}
        replay_candidates: list[tuple[ObservationContentManifest, ...]] = []
        any_redacted = False
        any_unavailable = False

        def content_binding_matches(
            content_kind: ObservationContentKind,
            correlation_identity: str | None,
            source_commitment: str | None,
        ) -> bool:
            """Select the binding contract after request admission.

            ``source_qualified_capture`` is derived only from the already
            validated capture-only request arm. Direct legacy coordinator
            calls retain their historical Codex materialization behavior.
            """

            checker = (
                observation_source_qualified_content_binding_matches
                if source_qualified_capture
                else observation_content_binding_matches
            )
            return checker(
                envelope,
                content_kind=content_kind,
                correlation_identity=correlation_identity,
                source_commitment=source_commitment,
            )

        async def capture_fence_current() -> bool:
            """Check the native capture fence before any persisted plaintext boundary."""

            if capture_fence is None:
                return True
            try:
                return await capture_fence()
            except Exception:
                return False

        async def verify_manifest(
            loaded: ObservationContentManifest,
        ) -> tuple[ObservationContentManifest, bool, bool]:
            """Rebind manifest metadata to the authenticated captured object."""

            if loaded.envelope_digest is None:
                return loaded, False, False
            try:
                if not await capture_fence_current():
                    return loaded, False, False
                ref = await runtime.objects.resolve_verified(
                    loaded.object_id, loaded.envelope_digest
                )
                if (
                    ref.metadata.kind is not ObjectKind.CAPTURED_CONTENT
                    or ref.metadata.media_type != "application/vnd.yoetz.observation-content+json"
                ):
                    return loaded, False, False
                raw = bytearray()
                async for chunk in runtime.objects.open_verified(ref):
                    raw.extend(chunk)
                    if len(raw) > ref.plaintext_size:
                        return loaded, False, False
                material = bytes(raw)
                if len(material) != ref.plaintext_size:
                    return loaded, False, False
                if not await capture_fence_current():
                    return loaded, False, False
                parsed = strict_json_parse(material)
                expected_keys = {
                    "format",
                    "content_kind",
                    "correlation_identity",
                    "source_commitment",
                    "media_type",
                    "part_index",
                    "part_count",
                    "redacted",
                    "content_b64",
                }
                if (
                    not isinstance(parsed, Mapping)
                    or set(parsed) != expected_keys
                    or canonical_encode(parsed) != material
                    or parsed.get("format") != "yoetz.observation-content/1"
                    or parsed.get("media_type") != "text/plain"
                    or type(parsed.get("content_b64")) is not str
                    or type(parsed.get("redacted")) is not bool
                ):
                    return loaded, False, False
                content = base64.b64decode(cast(str, parsed["content_b64"]), validate=True)
                verified = ObservationContentManifest(
                    object_id=ref.object_id,
                    envelope_digest=ref.envelope_digest,
                    content_kind=ObservationContentKind(cast(str, parsed["content_kind"])),
                    part_index=cast(int, parsed["part_index"]),
                    part_count=cast(int, parsed["part_count"]),
                    redacted=cast(bool, parsed["redacted"]),
                    content_digest="sha256:" + hashlib.sha256(content).hexdigest(),
                    content_bytes=len(content),
                    correlation_identity=cast(str, parsed["correlation_identity"]),
                    source_commitment=cast(str, parsed["source_commitment"]),
                )
                if not content_binding_matches(
                    verified.content_kind,
                    verified.correlation_identity,
                    verified.source_commitment,
                ):
                    return loaded, False, False
                return verified, True, verified == loaded
            except Exception:
                return loaded, False, False

        async def note_unavailable() -> None:
            await self._local(
                partial(
                    self.local.note_coverage_gap,
                    workspace,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
            )

        async def note_budget_exhausted() -> None:
            await self._local(
                partial(
                    self.local.note_coverage_gap,
                    workspace,
                    ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value,
                )
            )
            await note_unavailable()

        def manifests_complete(candidate: tuple[ObservationContentManifest, ...]) -> bool:
            parts: dict[
                tuple[str, ObservationContentKind],
                list[ObservationContentManifest],
            ] = {}
            for item in candidate:
                if item.correlation_identity is None or item.source_commitment is None:
                    return False
                key = (item.correlation_identity, item.content_kind)
                parts.setdefault(key, []).append(item)
            return bool(parts) and all(
                len({item.part_count for item in group}) == 1
                and len({item.source_commitment for item in group}) == 1
                and len({item.part_index for item in group}) == len(group)
                and {item.part_index for item in group} == set(range(group[0].part_count))
                for group in parts.values()
            )

        def legacy_source_group(item: ObservationContentManifest) -> str:
            correlation = item.correlation_identity
            if correlation is None or ":" not in correlation:
                return item.object_id
            return correlation.rsplit(":", 1)[0]

        # Content chunks are intentionally ephemeral at the hook boundary. If
        # the ledger commit wins a client-side timeout, the durable outbox retry
        # carries only the structural envelope. Recover the manifests that the
        # first attempt already bound to this normalized phase so equivalent
        # hook/stream copies reconstruct the same original role set
        # and find the committed operation (#539).
        recovered_current = store.content_manifests_for_logical_identity(
            workspace=workspace,
            logical_identity=content_identity,
        )
        # Upgrade recovery for manifests written before issue #539 added the
        # phase-scoped content identity. The matching source group may supply
        # usable content; every legacy source group is also kept separately as
        # lookup-only input, because an equivalent post-upgrade stream copy has
        # a different source identity but the same committed operation roles.
        recovered_legacy_same_source: list[ObservationContentManifest] = []
        recovered_legacy_all: list[ObservationContentManifest] = []
        # The raw canonical identity is the pre-#539 manifest key. Keep both
        # that shape and the phase-scoped identities used by newer writers;
        # the mapping-version variants cover rows written before #607 widened
        # canonical identity with source lane and generation.
        recovery_identities = (
            content_identity,
            logical_identity,
            *legacy_content_identities,
            *legacy_logical_identities,
        )
        for candidate_identity in dict.fromkeys(recovery_identities):
            recovered_legacy_same_source.extend(
                store.content_manifests_for_logical_identity(
                    workspace=workspace,
                    logical_identity=candidate_identity,
                    correlation_identity_prefix=f"{envelope.source_identity}:",
                )
            )
            recovered_legacy_all.extend(
                store.content_manifests_for_logical_identity(
                    workspace=workspace,
                    logical_identity=candidate_identity,
                )
            )
        recovered_legacy_same_source_tuple = tuple(recovered_legacy_same_source)
        legacy_groups: dict[str, list[ObservationContentManifest]] = {}
        for item in recovered_legacy_all:
            legacy_groups.setdefault(legacy_source_group(item), []).append(item)
        recovered_sets: list[tuple[ObservationContentManifest, ...]] = []
        for candidate in (
            recovered_current,
            recovered_legacy_same_source_tuple,
            *(
                tuple(sorted(group, key=lambda item: item.object_id.encode()))
                for group in legacy_groups.values()
            ),
        ):
            if candidate and candidate not in recovered_sets:
                recovered_sets.append(candidate)
        # Keep object identity here: the loop below deliberately admits
        # captured roles only for the primary same-phase/source candidate.
        # Re-wrapping a list as a tuple would make ``candidate is
        # primary_recovered`` false and silently turn every historical retry
        # into replay-only evidence.
        primary_recovered = recovered_current or recovered_legacy_same_source_tuple
        for candidate in recovered_sets:
            complete = manifests_complete(candidate)
            if not complete:
                any_unavailable = True
                await note_unavailable()
            raw_candidate = tuple(sorted(candidate, key=lambda item: item.object_id.encode()))
            verified_candidate: list[ObservationContentManifest] = []
            verified_rows: list[
                tuple[ObservationContentManifest, ObservationContentManifest, bool, bool]
            ] = []
            for loaded in candidate:
                verified, readable, exact = await verify_manifest(loaded)
                verified_candidate.append(verified if readable else loaded)
                verified_rows.append((loaded, verified, readable, exact))
                if not exact:
                    any_unavailable = True
                    await note_unavailable()
            candidate_usable = complete and all(
                readable and exact and loaded.content_digest is not None
                for loaded, _verified, readable, exact in verified_rows
            )
            if candidate is primary_recovered and candidate_usable:
                for loaded, verified, readable, exact in verified_rows:
                    # A legacy-unbound row was intentionally excluded by the
                    # materializer that may already have committed it. Reading
                    # its object now must not silently add a captured role.
                    assert readable and exact and loaded.content_digest is not None
                    manifests[verified.object_id] = verified
                    any_redacted = any_redacted or verified.redacted
            normalized_verified = tuple(
                sorted(verified_candidate, key=lambda item: item.object_id.encode())
            )
            for replay_candidate in (raw_candidate, normalized_verified):
                if replay_candidate and replay_candidate not in replay_candidates:
                    replay_candidates.append(replay_candidate)

        # Once a phase has durable manifests its materialized role set is
        # frozen. Equivalent hook/stream copies may carry fresh ephemeral
        # chunks, but adding those roles after a commit would change the stable
        # operation identity. The existing set remains authoritative.
        freeze_roles = bool(primary_recovered) and not allow_incomplete_recovery
        for chunk in chunks:
            if not content_binding_matches(
                chunk.content_kind,
                chunk.correlation_identity,
                chunk.source_commitment,
            ):
                any_unavailable = True
                await note_unavailable()
                continue
            if chunk.media_type != "text/plain":
                any_unavailable = True
                await note_unavailable()
                continue
            existing = store.content_manifest_object_id(
                workspace=workspace,
                logical_identity=content_identity,
                chunk=chunk,
            )
            if existing is not None:
                if existing in manifests:
                    continue
                loaded = store.load_content_manifest(existing)
                if loaded is not None and loaded.content_digest is not None:
                    verified, readable, exact = await verify_manifest(loaded)
                    if not exact:
                        any_unavailable = True
                        await note_unavailable()
                    if readable and exact:
                        manifests[verified.object_id] = verified
                        any_redacted = any_redacted or verified.redacted
                    continue
            if freeze_roles:
                any_unavailable = True
                await note_unavailable()
                continue
            if not await capture_fence_current():
                any_unavailable = True
                await note_unavailable()
                continue
            scan = prepare_persisted_plaintext(chunk.content)
            if not scan.persist:
                any_redacted = any_redacted or scan.redacted
                any_unavailable = True
                await self._local(
                    partial(
                        self.local.note_coverage_gap,
                        workspace,
                        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                    )
                )
                continue
            safe_content = scan.content
            detected = scan.redacted
            any_redacted = any_redacted or chunk.redacted or detected
            stored_chunk = replace(
                chunk,
                content=safe_content,
                redacted=chunk.redacted or detected,
            )
            manifest_bytes = canonical_encode(
                JsonObject(
                    {
                        "format": "yoetz.observation-content/1",
                        "content_kind": stored_chunk.content_kind.value,
                        "correlation_identity": stored_chunk.correlation_identity,
                        "source_commitment": stored_chunk.source_commitment,
                        "media_type": stored_chunk.media_type,
                        "part_index": stored_chunk.part_index,
                        "part_count": stored_chunk.part_count,
                        "redacted": stored_chunk.redacted,
                        "content_b64": base64.b64encode(safe_content).decode("ascii"),
                    }
                )
            )
            finalized_now: StagedObject | None = None
            if existing is None:
                metadata = ObjectMetadata(
                    ObjectKind.CAPTURED_CONTENT,
                    "application/vnd.yoetz.observation-content+json",
                    runtime.task_id,
                    self.clock.now_utc(),
                )
                if not await capture_fence_current():
                    any_unavailable = True
                    await note_unavailable()
                    continue
                staged = await runtime.objects.stage(
                    ObjectSource(data=manifest_bytes, declared_size=len(manifest_bytes)),
                    metadata,
                )
                if not await capture_fence_current():
                    await runtime.objects.abandon(staged)
                    any_unavailable = True
                    await note_unavailable()
                    continue
                ref = await runtime.objects.finalize(staged)
                finalized_now = staged
            else:
                loaded = store.load_content_manifest(existing)
                if loaded is None or loaded.envelope_digest is None:
                    any_unavailable = True
                    await self._local(
                        partial(
                            self.local.note_coverage_gap,
                            workspace,
                            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                        )
                    )
                    continue
                try:
                    ref = await runtime.objects.resolve_verified(
                        loaded.object_id, loaded.envelope_digest
                    )
                except Exception:
                    any_unavailable = True
                    await self._local(
                        partial(
                            self.local.note_coverage_gap,
                            workspace,
                            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                        )
                    )
                    continue
            content_digest = "sha256:" + hashlib.sha256(safe_content).hexdigest()
            # The object may already be durable. Recheck authority before
            # binding its manifest. A revoke that wins after finalization must
            # not record captured evidence for the old fence. Only an object
            # this attempt just finalized, and that no manifest row names, is
            # abandoned. A row that already names an object is its owner.
            if not await capture_fence_current():
                if finalized_now is not None:
                    await self._abandon_captured_object_if_unowned(
                        runtime,
                        store,
                        finalized_now,
                        workspace=workspace,
                        logical_identity=content_identity,
                        chunk=stored_chunk,
                        object_id=ref.object_id,
                    )
                any_unavailable = True
                await note_unavailable()
                continue
            try:
                store.record_content_manifest(
                    workspace=workspace,
                    logical_identity=content_identity,
                    chunk=stored_chunk,
                    ref=ref,
                    content_digest=content_digest,
                    content_bytes=len(safe_content),
                    recorded_at=timestamp_from_datetime(self.clock.now_utc()),
                )
            except BaseException as exc:
                # Store failures, including LIMIT_EXCEEDED, are raised inside
                # the manifest transaction or before it. This call's row did
                # not commit. Abandon only the object finalized here, and only
                # when a lookup proves the row does not name it. An unknown
                # lookup is not that proof. The budget fence still stops later
                # parts; it no longer retains an unowned finalized object.
                if finalized_now is not None:
                    await self._abandon_captured_object_if_unowned(
                        runtime,
                        store,
                        finalized_now,
                        workspace=workspace,
                        logical_identity=content_identity,
                        chunk=stored_chunk,
                        object_id=ref.object_id,
                    )
                if type(exc) is PublicOperationError and exc.code is PublicErrorCode.LIMIT_EXCEEDED:
                    any_unavailable = True
                    self._capture_budget_exhausted = True
                    await note_budget_exhausted()
                    break
                raise
            if stored_chunk.content_kind is ObservationContentKind.WORKSPACE_LOCATOR:
                store.bind_workspace_locator(
                    workspace=workspace,
                    locator_ref=ref,
                    bound_at=timestamp_from_datetime(self.clock.now_utc()),
                )
            loaded = store.load_content_manifest(ref.object_id)
            if loaded is None or loaded.content_digest is None:
                any_unavailable = True
                await self._local(
                    partial(
                        self.local.note_coverage_gap,
                        workspace,
                        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                    )
                )
                continue
            manifests[loaded.object_id] = loaded

        usable_manifests = tuple(
            sorted(manifests.values(), key=lambda item: item.object_id.encode())
        )
        if expected_capture_parts is not None:
            recovered_parts = tuple(
                sorted(
                    (
                        item.content_kind.value,
                        cast(str, item.correlation_identity),
                        cast(str, item.source_commitment),
                        item.part_index,
                        item.part_count,
                    )
                    for item in usable_manifests
                )
            )
            if recovered_parts != expected_capture_parts:
                usable_manifests = ()
                any_unavailable = True
                await note_unavailable()
        if usable_manifests and not manifests_complete(usable_manifests):
            # The first ingest can itself carry only a prefix of a multipart
            # value. Persisting that prefix helps a later exact retry, but it
            # cannot become immutable captured evidence on its own.
            usable_manifests = ()
            any_unavailable = True
            await note_unavailable()

        # Durable refs are assertions from the incoming envelope, not authority
        # to borrow a manifest from another phase. Correct phase-bound refs were
        # already recovered above; every other ref weakens coverage.
        for ref in envelope.content_object_refs:
            if not ref.startswith("obj_") or any(
                item.object_id == ref for item in usable_manifests
            ):
                continue
            any_unavailable = True
            await note_unavailable()
        return (
            usable_manifests,
            tuple(replay_candidates),
            any_redacted,
            any_unavailable,
        )

    async def _enqueue_verification(
        self,
        runtime: TaskRuntime,
        workspace: str,
        store: TaskObservationPort,
        envelope: ObservationEnvelope,
        *,
        codex_session_id: str | None = None,
        legacy_session_id: str | None = None,
        legacy_writer_id: str | None = None,
    ) -> None:
        """Capture subject state, enqueue durable work, wake the supervisor.

        When no supervisor is attached (unit tests), drain inline so existing
        scenarios keep completing within the same await.
        """

        worker = await self._prepare_verification_worker(
            runtime,
            workspace,
            store,
            envelope,
            codex_session_id=codex_session_id,
            legacy_session_id=legacy_session_id,
            legacy_writer_id=legacy_writer_id,
        )
        if worker is None:
            return
        if self.verification_supervisor is not None:
            supervisor = self.verification_supervisor
            if supervisor.has_handle(workspace, runtime.task_id):
                supervisor.notify(workspace)
                return

            deferred_runtime = await self._route_observation_runtime(
                runtime.task_id, runtime.session_id
            )
            try:
                deferred_store = self._observation_store(deferred_runtime)
                deferred_worker = await self._rebuild_verification_worker(
                    deferred_runtime,
                    workspace,
                    deferred_store,
                    legacy_session_id=legacy_session_id,
                    legacy_writer_id=legacy_writer_id,
                )
                if deferred_worker is None:
                    await self.runtime.release(deferred_runtime)
                    return

                async def _after() -> None:
                    await self._run_advice(
                        workspace,
                        deferred_runtime,
                        deferred_store,
                        legacy_writer_id=legacy_writer_id,
                        session_commitment=envelope.session_commitment,
                    )

                async def _release() -> None:
                    await self.runtime.release(deferred_runtime)

                async def _failed() -> None:
                    await self._local(
                        partial(
                            self.local.note_session_coverage_gap,
                            workspace,
                            envelope.session_commitment,
                            ObservationGapCode.VERIFICATION_STALE.value,
                        )
                    )

                registered = supervisor.register(
                    VerificationDrainHandle(
                        workspace_commitment=workspace,
                        worker=deferred_worker,
                        after_complete=_after,
                        on_idle=_release,
                        task_id=runtime.task_id,
                        on_failure=_failed,
                    )
                )
                if not registered:
                    await self.runtime.release(deferred_runtime)
            except BaseException:
                await self.runtime.release(deferred_runtime)
                raise
            supervisor.notify(workspace)
            return
        while await worker.run_once() is not None:
            pass

    async def _prepare_verification_worker(
        self,
        runtime: TaskRuntime,
        workspace: str,
        store: TaskObservationPort,
        envelope: ObservationEnvelope,
        *,
        codex_session_id: str | None = None,
        legacy_session_id: str | None = None,
        legacy_writer_id: str | None = None,
    ) -> ObservationVerificationWorker | None:
        """Build a worker and enqueue if subject state changed; never run checks here."""

        if envelope.event_kind != "PostToolUse" and not stream_event_is_completed_tool(
            envelope.event_kind, envelope.structural_payload
        ):
            return None
        # Older READY generations may rediscover a pending verification row without the original
        # ingest callback.  Repair its route only when the durable mapping still names this exact
        # runtime/session and the raw host session is not ended.  Normal ingest records the route
        # at admission above; this gate keeps the recovery repair from becoming a predecessor
        # binding bypass when an ended mapping was rewritten to a successor.
        route_recorder = getattr(store, "record_workspace_session_route", None)
        route_allowed = (
            type(legacy_session_id) is str
            and runtime.session_id == legacy_session_id
            and type(runtime.writer_id) is str
            and runtime.writer_id
            in {
                legacy_writer_id,
                observation_writer_id(runtime.task_id, legacy_session_id),
            }
        )
        if route_allowed and codex_session_id is not None:
            ended_lookup = getattr(self.local, "codex_session_ended", None)
            if callable(ended_lookup):
                try:
                    route_allowed = not await self._local(
                        partial(ended_lookup, workspace, codex_session_id)
                    )
                except Exception:
                    route_allowed = False
        if callable(route_recorder) and route_allowed:
            now = timestamp_from_datetime(self.clock.now_utc())
            route_recorder(
                workspace=workspace,
                yoetz_session_id=runtime.session_id,
                yoetz_task_id=runtime.task_id,
                yoetz_writer_id=runtime.writer_id,
                codex_session_commitment=envelope.session_commitment,
                bound_at=now,
            )
        required = (
            "workspace_locator_descriptor",
            "verification_repository",
            "latest_verification_subject_digest",
            "policy_digest_is_trusted",
            "record_trusted_check_policy",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            return None
        descriptor = store.workspace_locator_descriptor(workspace)
        if descriptor is None:
            await self._local(
                partial(
                    self.local.note_coverage_gap,
                    workspace,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
            )
            return None
        locator_ref = await runtime.objects.resolve_verified(*descriptor)
        encrypted = b"".join([chunk async for chunk in runtime.objects.open_verified(locator_ref)])
        parsed = strict_json_parse(encrypted)
        if not isinstance(parsed, dict) and type(parsed) is not JsonObject:
            return None
        content_b64 = parsed.get("content_b64")
        content_kind = parsed.get("content_kind")
        if (
            content_kind != ObservationContentKind.WORKSPACE_LOCATOR.value
            or type(content_b64) is not str
        ):
            return None
        try:
            locator = base64.b64decode(content_b64.encode("ascii"), validate=True).decode("utf-8")
            handle = open_local_workspace(Path(locator))
            policy, _raw_policy = load_observation_check_policy(Path(locator))
        except ObservationCheckPolicyAbsent:
            # No approved-check policy is the ordinary opt-in state, not lost content capture.
            return None
        except Exception:
            await self._local(
                partial(
                    self.local.note_coverage_gap,
                    workspace,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
            )
            return None
        now = timestamp_from_datetime(self.clock.now_utc())
        if not await self._local(
            partial(self.local.policy_digest_is_trusted, workspace, policy.raw_digest)
        ):
            await self._local(
                partial(
                    self.local.note_coverage_gap,
                    workspace,
                    ObservationGapCode.POLICY_UNTRUSTED.value,
                )
            )
            return None
        if not store.policy_digest_is_trusted(workspace, policy.raw_digest):
            trust_payload = canonical_encode(
                JsonObject(
                    {
                        "format": "yoetz.approved-check-policy-trust/1",
                        "workspace_commitment": workspace,
                        "policy_digest": policy.raw_digest,
                        "trusted_at": now.wire,
                    }
                )
            )
            trust_ref = await self._encrypt_captured_content(runtime, trust_payload)
            store.record_trusted_check_policy(
                workspace=workspace,
                policy_digest=policy.raw_digest,
                trust_ref=trust_ref,
                trusted_at=now,
            )
        capture = GitSubjectStateAdapter()

        def subject_digest(_handle: object) -> str:
            result = capture.capture(
                SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
            )
            if result.subject_state is None:
                raise RuntimeError("subject_state_unavailable")
            return canonical_digest(
                JsonObject(
                    {
                        "tree_digest": result.subject_state.tree_digest,
                        "diff_digest": result.subject_state.diff_digest,
                    }
                )
            )

        current_digest = await asyncio.to_thread(subject_digest, handle)
        repository = cast(ObservationVerificationRepository, store.verification_repository())

        async def persist_output(job: ObservationVerificationJob, content: bytes) -> str | None:
            return await self._persist_approved_check_output(
                runtime, store, workspace, job, content
            )

        def now_wire() -> str:
            return timestamp_from_datetime(self.clock.now_utc()).wire

        def lease_expiry() -> str:
            return timestamp_from_datetime(self.clock.now_utc() + timedelta(minutes=2)).wire

        worker = ObservationVerificationWorker(
            repository=repository,
            runner=ApprovedCheckRunner({item.approval_commitment: item for item in policy.checks}),
            workspace_provider=lambda _workspace: handle,
            policy_provider=lambda _workspace, _digest: policy.checks,
            capture_subject_state=subject_digest,
            persist_output=persist_output,
            service_generation=runtime.fence.service_generation,
            lease_owner=runtime.fence.service_instance_id,
            now=now_wire,
            lease_expires_at=lease_expiry,
            materialize_result=lambda completed: self._materialize_approved_check(
                runtime,
                completed,
                legacy_session_id=legacy_session_id,
                legacy_writer_id=legacy_writer_id,
            ),
        )
        worker.enqueue_if_changed(
            workspace=workspace,
            policy_digest=policy.raw_digest,
            approvals=policy.checks,
            previous_subject_state_digest=store.latest_verification_subject_digest(workspace),
            subject_state_digest=current_digest,
        )
        # Persist inspection snapshot after verification setup.  The session route is bound
        # above, before policy loading, because policy setup is optional for content selection.
        inspect_recorder = getattr(store, "record_inspection_snapshot", None)
        inspect_loader = getattr(store, "load_inspection_snapshot", None)
        inspection_snapshot: ObservationInspectionSnapshot | None = None
        if callable(inspect_loader):
            inspection_snapshot = cast(
                ObservationInspectionSnapshot | None,
                inspect_loader(
                    workspace=workspace,
                    yoetz_session_id=runtime.session_id,
                    subject_state_digest=current_digest,
                ),
            )
        if inspection_snapshot is None and callable(inspect_recorder):
            relative_paths: tuple[str, ...] = ()
            changed_digest = current_digest
            facts_ref: ObjectRef | None = None
            facts_content_digest: str | None = None
            facts_content_bytes: int | None = None
            excerpt_ref: ObjectRef | None = None
            excerpt_content_digest: str | None = None
            excerpt_content_bytes: int | None = None
            excerpt_redacted = False
            excerpt_truncated = False
            try:
                relative_paths = list_changed_relative_paths(handle)
                changed_digest = canonical_digest(
                    JsonObject({"relative_paths": list(relative_paths)})
                )
                orchestration = orchestrate_changed_path_inspection(
                    workspace=handle,
                    inspect_port=LocalWorkspaceInspectAdapter(),
                    relative_paths=relative_paths,
                    changed_paths_digest=changed_digest,
                )
                if orchestration.inspect_fact is not None:
                    fact_bytes = canonical_encode(
                        JsonObject(
                            {
                                "format": "yoetz.observation-inspect-fact/1",
                                "selection_digest": orchestration.inspect_fact.selection_digest,
                                "relative_paths": list(orchestration.inspect_fact.relative_paths),
                                "changed_paths_digest": changed_digest,
                            }
                        )
                    )
                    facts_ref = await self._encrypt_captured_content(runtime, fact_bytes)
                    facts_content_digest = "sha256:" + hashlib.sha256(fact_bytes).hexdigest()
                    facts_content_bytes = len(fact_bytes)
                if orchestration.inspect is not None and orchestration.inspect.artifacts:
                    (
                        excerpt_bytes,
                        excerpt_unavailable,
                        excerpt_redacted,
                        excerpt_truncated,
                    ) = build_inspection_excerpt_manifest(orchestration.inspect.artifacts)
                    if excerpt_unavailable:
                        await self._local(
                            partial(
                                self.local.note_coverage_gap,
                                workspace,
                                ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                            )
                        )
                    elif excerpt_bytes is not None:
                        excerpt_ref = await self._encrypt_captured_content(runtime, excerpt_bytes)
                        excerpt_content_digest = (
                            "sha256:" + hashlib.sha256(excerpt_bytes).hexdigest()
                        )
                        excerpt_content_bytes = len(excerpt_bytes)
            except Exception:
                await self._local(
                    partial(
                        self.local.note_coverage_gap,
                        workspace,
                        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                    )
                )
                relative_paths = ()
            inspect_recorder(
                workspace=workspace,
                yoetz_session_id=runtime.session_id,
                subject_state_digest=current_digest,
                changed_paths_digest=changed_digest,
                relative_paths=relative_paths,
                facts_ref=facts_ref,
                facts_content_digest=facts_content_digest,
                facts_content_bytes=facts_content_bytes,
                excerpt_ref=excerpt_ref,
                excerpt_content_digest=excerpt_content_digest,
                excerpt_content_bytes=excerpt_content_bytes,
                excerpt_redacted=excerpt_redacted,
                excerpt_truncated=excerpt_truncated,
                recorded_at=now,
            )
            if callable(inspect_loader):
                inspection_snapshot = cast(
                    ObservationInspectionSnapshot | None,
                    inspect_loader(
                        workspace=workspace,
                        yoetz_session_id=runtime.session_id,
                        subject_state_digest=current_digest,
                    ),
                )
        if inspection_snapshot is None:
            await self._local(
                partial(
                    self.local.note_coverage_gap,
                    workspace,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
            )
        if inspection_snapshot is not None:
            inspection_result = await self._append_inspection_snapshot(runtime, inspection_snapshot)
            if inspection_result is not None and codex_session_id is not None:
                await self._local(
                    partial(
                        self.local.note_frontier_motion,
                        workspace,
                        codex_session_id,
                        from_sequence=inspection_result.subject_frontier.sequence,
                        to_sequence=inspection_result.result_frontier.sequence,
                        head_digest=inspection_result.result_frontier.head_digest,
                        observation_record_count=len(inspection_result.accepted),
                        task_id=runtime.task_id,
                    )
                )
        return worker

    async def _rebuild_verification_worker(
        self,
        runtime: TaskRuntime,
        workspace: str,
        store: TaskObservationPort,
        *,
        legacy_session_id: str | None = None,
        legacy_writer_id: str | None = None,
    ) -> ObservationVerificationWorker | None:
        """Rebuild a drain worker for already-pending durable jobs (no enqueue)."""

        required = (
            "workspace_locator_descriptor",
            "verification_repository",
            "policy_digest_is_trusted",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            return None
        descriptor = store.workspace_locator_descriptor(workspace)
        if descriptor is None:
            return None
        locator_ref = await runtime.objects.resolve_verified(*descriptor)
        encrypted = b"".join([chunk async for chunk in runtime.objects.open_verified(locator_ref)])
        parsed = strict_json_parse(encrypted)
        if not isinstance(parsed, dict) and type(parsed) is not JsonObject:
            return None
        content_b64 = parsed.get("content_b64")
        content_kind = parsed.get("content_kind")
        if (
            content_kind != ObservationContentKind.WORKSPACE_LOCATOR.value
            or type(content_b64) is not str
        ):
            return None
        try:
            locator = base64.b64decode(content_b64.encode("ascii"), validate=True).decode("utf-8")
            handle = open_local_workspace(Path(locator))
            policy, _raw_policy = load_observation_check_policy(Path(locator))
        except Exception:
            return None
        if not store.policy_digest_is_trusted(workspace, policy.raw_digest):
            return None
        capture = GitSubjectStateAdapter()

        def subject_digest(_handle: object) -> str:
            result = capture.capture(
                SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
            )
            if result.subject_state is None:
                raise RuntimeError("subject_state_unavailable")
            return canonical_digest(
                JsonObject(
                    {
                        "tree_digest": result.subject_state.tree_digest,
                        "diff_digest": result.subject_state.diff_digest,
                    }
                )
            )

        repository = cast(ObservationVerificationRepository, store.verification_repository())

        async def persist_output(job: ObservationVerificationJob, content: bytes) -> str | None:
            return await self._persist_approved_check_output(
                runtime, store, workspace, job, content
            )

        def now_wire() -> str:
            return timestamp_from_datetime(self.clock.now_utc()).wire

        def lease_expiry() -> str:
            return timestamp_from_datetime(self.clock.now_utc() + timedelta(minutes=2)).wire

        return ObservationVerificationWorker(
            repository=repository,
            runner=ApprovedCheckRunner({item.approval_commitment: item for item in policy.checks}),
            workspace_provider=lambda _workspace: handle,
            policy_provider=lambda _workspace, _digest: policy.checks,
            capture_subject_state=subject_digest,
            persist_output=persist_output,
            service_generation=runtime.fence.service_generation,
            lease_owner=runtime.fence.service_instance_id,
            now=now_wire,
            lease_expires_at=lease_expiry,
            materialize_result=lambda completed: self._materialize_approved_check(
                runtime,
                completed,
                legacy_session_id=legacy_session_id,
                legacy_writer_id=legacy_writer_id,
            ),
        )

    async def _run_verification(
        self,
        runtime: TaskRuntime,
        workspace: str,
        store: TaskObservationPort,
        envelope: ObservationEnvelope,
    ) -> None:
        """Deprecated alias: enqueue (+ inline drain without supervisor)."""

        await self._enqueue_verification(runtime, workspace, store, envelope)

    async def _persist_approved_check_output(
        self,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        workspace: str,
        job: ObservationVerificationJob,
        content: bytes,
    ) -> str | None:
        """Encrypt approved-check output only after the shared fail-closed scan."""

        scan = prepare_persisted_plaintext(content)
        if not scan.persist:
            await self._local(
                partial(
                    self.local.note_coverage_gap,
                    workspace,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
            )
            return None
        chunk = ObservationContentChunk(
            content_kind=ObservationContentKind.APPROVED_CHECK_OUTPUT,
            correlation_identity=f"check:{job.job_id}",
            source_commitment=f"hmac-sha256:{'0' * 64}",
            media_type="text/plain",
            part_index=0,
            part_count=1,
            content=scan.content,
            redacted=scan.redacted,
        )
        manifest = canonical_encode(
            JsonObject(
                {
                    "format": "yoetz.observation-content/1",
                    "content_kind": chunk.content_kind.value,
                    "correlation_identity": chunk.correlation_identity,
                    "source_commitment": chunk.source_commitment,
                    "media_type": chunk.media_type,
                    "part_index": 0,
                    "part_count": 1,
                    "redacted": scan.redacted,
                    "content_b64": base64.b64encode(scan.content).decode("ascii"),
                }
            )
        )
        staged, ref = await self._stage_captured_content(runtime, manifest)
        content_digest = "sha256:" + hashlib.sha256(scan.content).hexdigest()
        logical_identity = f"verification:{job.job_id}"
        try:
            store.record_content_manifest(
                workspace=workspace,
                logical_identity=logical_identity,
                chunk=chunk,
                ref=ref,
                content_digest=content_digest,
                content_bytes=len(scan.content),
                recorded_at=timestamp_from_datetime(self.clock.now_utc()),
            )
        except BaseException:
            await self._abandon_captured_object_if_unowned(
                runtime,
                store,
                staged,
                workspace=workspace,
                logical_identity=logical_identity,
                chunk=chunk,
                object_id=ref.object_id,
            )
            raise
        return ref.object_id

    async def _stage_captured_content(
        self, runtime: TaskRuntime, content: bytes
    ) -> tuple[StagedObject, ObjectRef]:
        metadata = ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "application/vnd.yoetz.observation-content+json",
            runtime.task_id,
            self.clock.now_utc(),
        )
        staged = await runtime.objects.stage(
            ObjectSource(data=content, declared_size=len(content)), metadata
        )
        return staged, await runtime.objects.finalize(staged)

    async def _encrypt_captured_content(self, runtime: TaskRuntime, content: bytes) -> ObjectRef:
        _staged, ref = await self._stage_captured_content(runtime, content)
        return ref

    async def _abandon_captured_object_if_unowned(
        self,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        staged: StagedObject,
        *,
        workspace: str,
        logical_identity: str,
        chunk: ObservationContentChunk,
        object_id: str,
    ) -> None:
        """Abandon one captured object whose manifest reference did not commit.

        ``abandon`` may remove finalized bytes only while the caller proves the
        reference was not submitted to a durable owner. A manifest row that
        names ``object_id`` is that owner. A lookup that fails is not proof, so
        the object stays for generation-fenced GC. Abandon failure is logged as
        ``observation_object_abandon_failed`` and does not replace the caller's
        error. The log id derives from the random object id, never from the
        captured bytes, so the diagnostic cannot fingerprint content.
        """

        if self._manifest_names_captured_object(
            store,
            workspace=workspace,
            logical_identity=logical_identity,
            chunk=chunk,
            object_id=object_id,
        ):
            return
        await abandon_preappend_objects(
            runtime.objects,
            (staged,),
            component="application.observation_coordinator",
            operation="observation_object_abandon_failed",
            request_id=self._captured_abandon_request_id(object_id),
        )

    def _captured_abandon_request_id(self, object_id: str) -> str:
        return self._stable_operation_id(
            canonical_digest(
                JsonObject({"operation": "observation_captured_abandon", "object_id": object_id})
            )
        )

    def _manifest_names_captured_object(
        self,
        store: TaskObservationPort,
        *,
        workspace: str,
        logical_identity: str,
        chunk: ObservationContentChunk,
        object_id: str,
    ) -> bool:
        """True when a committed row names this object, or the lookup is unknown."""

        try:
            named = store.content_manifest_object_id(
                workspace=workspace,
                logical_identity=logical_identity,
                chunk=chunk,
            )
        except Exception:
            return True
        return named == object_id

    def _stable_operation_id(self, digest: str) -> str:
        # Derive a request-shaped id from the digest for idempotent appends.
        material = digest.removeprefix("sha256:")
        # Use IdPort when available for uniqueness shape; fall back to deterministic hex.
        try:
            # Prefer deterministic UUID from digest bytes.
            import uuid as _uuid

            raw = bytes.fromhex(material[:32])
            arr = bytearray(raw)
            arr[6] = (arr[6] & 0x0F) | 0x40
            arr[8] = (arr[8] & 0x3F) | 0x80
            from yoetz.protocol.ids import PREFIX_BY_KIND

            return PREFIX_BY_KIND[IdKind.REQUEST] + str(_uuid.UUID(bytes=bytes(arr)))
        except ValueError, TypeError:
            return self.ids.new(IdKind.REQUEST)

    async def _lineage_refs_for_advice(
        self,
        parent_task_id: str,
        envelopes: tuple[ObservationEnvelope, ...],
    ) -> tuple[tuple[str, str], ...]:
        """Resolve retained host observations to service-owned annotation or child IDs."""

        registry = self.host_lineage_registry
        if registry is None:
            return ()
        resolver = registry.find_host_lineage_observation
        resolved: dict[tuple[str, str, str | None], str | None] = {}
        refs: list[tuple[str, str]] = []
        for envelope in envelopes:
            observation = host_lineage_from_envelope(envelope)
            if observation is None:
                continue
            correlation = observation.correlation
            key = (correlation.host, correlation.subagent_id, correlation.parent_tool_call_id)
            if key not in resolved:
                try:
                    annotation = await resolver(parent_task_id, observation)
                except HostLineageRegistryError:
                    annotation = None
                resolved[key] = (
                    None
                    if annotation is None
                    else (annotation.bound_child_task_id or annotation.correlation_id)
                )
            reference = resolved[key]
            if reference is not None:
                refs.append((envelope.source_identity, reference))
        return tuple(sorted(refs, key=lambda item: item[0].encode("ascii")))

    async def _run_advice(
        self,
        workspace: str,
        runtime: TaskRuntime | str,
        store: TaskObservationPort,
        *,
        legacy_writer_id: str | None = None,
        session_commitment: str | None = None,
    ) -> None:
        # A plain string is a bare task id from callers with no runtime in hand;
        # anything else is runtime-shaped (the concrete TaskRuntime in
        # production, duck-typed stand-ins in tests).
        task_id = runtime if isinstance(runtime, str) else runtime.task_id
        session_id = None if isinstance(runtime, str) else runtime.session_id
        if session_commitment is None and type(session_id) is str:
            # Post-commit callers (verification drains, restart rediscovery)
            # carry no envelope; recover the mapped Codex session commitment
            # from the durable route so the build stays session-scoped (#352).
            route_lookup = getattr(store, "codex_session_commitment_for_session", None)
            if callable(route_lookup):
                routed = route_lookup(workspace=workspace, yoetz_session_id=session_id)
                if type(routed) is str:
                    session_commitment = routed
        envelopes = scoped_session_envelopes(store, workspace, session_commitment)
        lineage_refs = await self._lineage_refs_for_advice(task_id, envelopes)
        snapshot = await self.advice_context_builder.build(
            workspace,
            store,
            yoetz_session_id=session_id if type(session_id) is str else None,
            session_commitment=session_commitment,
            lineage_refs=lineage_refs,
        )
        if snapshot is not None:
            # Materialize before publishing the snapshot to either durable cache.
            # Snapshot identity participates in deterministic suppression, so
            # advancing it first could make a failed ledger append disappear on
            # retry and let the outbox ACK without the finding ever landing.
            if not isinstance(runtime, str) and runtime.writer_id is not None:
                await self._materialize_advice_findings(
                    runtime,
                    envelopes,
                    snapshot,
                    store=store,
                    legacy_writer_id=legacy_writer_id,
                )
            now = timestamp_from_datetime(self.clock.now_utc())
            store.set_advice_snapshot(workspace, snapshot, now)
            session_setter = getattr(store, "set_session_advice_snapshot", None)
            if callable(session_setter) and type(session_id) is str:
                session_setter(
                    workspace=workspace,
                    yoetz_session_id=session_id,
                    snapshot=snapshot,
                    updated_at=now,
                )
            recorder = getattr(store, "record_advice_history", None)
            if callable(recorder):
                recorder(
                    workspace=workspace,
                    snapshot=snapshot,
                    verification_state=(
                        "stale"
                        if ObservationGapCode.VERIFICATION_STALE.value
                        in snapshot.confidence_coverage.known_gaps
                        else "unavailable"
                    ),
                    semantic_state=snapshot.semantic_attempt_state,
                    freshness=(
                        "current" if not snapshot.confidence_coverage.known_gaps else "partial"
                    ),
                    recorded_at=now,
                )
            # Mirror into local store for hook advice delivery.
            await self._local(partial(self.local.set_advice_snapshot, workspace, snapshot))
            if not isinstance(runtime, str) and type(session_id) is str:
                await self._local(
                    partial(
                        self.local.set_session_advice_snapshot,
                        workspace,
                        yoetz_session_id=session_id,
                        snapshot=snapshot,
                    )
                )
            if (
                ADVICE_SEMANTIC_PENDING_GAP in snapshot.confidence_coverage.known_gaps
                and not isinstance(runtime, str)
            ):
                await self._register_advice_semantic_drain(
                    workspace,
                    runtime,
                    legacy_writer_id=legacy_writer_id,
                    session_commitment=session_commitment,
                )
        if self.advice_hook is not None:
            result = self.advice_hook(
                workspace_commitment=workspace,
                task_id=task_id,
                store=store,
                envelopes=envelopes,
                frontier=None if snapshot is None else snapshot.freshness_frontier,
            )
            if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
                await cast(Awaitable[None], result)

    async def rediscover_pending_advice_semantic(self) -> None:
        """Re-register drains for workspaces whose AI-powered advice rows are still pending.

        Runs once after the ready-lifecycle supervisor starts. A row left ``running`` by a
        previous service generation is reclaimed by ``claim_next`` and re-attempted; it is never
        reported as a success (#619).
        """

        supervisor = self.advice_semantic_supervisor
        if supervisor is None or self.advice_semantic_dispatch is None:
            return
        for workspace in await self._local(self.local.list_consented_workspaces):
            await self._rediscover_workspace_pending_advice_semantic(supervisor, workspace)
        supervisor.notify()

    async def _rediscover_workspace_pending_advice_semantic(
        self,
        supervisor: ObservationAdviceSemanticSupervisor,
        workspace: str,
    ) -> None:
        if supervisor.closed or supervisor.has_handle(workspace):
            return
        consent = await self._local(partial(self.local.consent_for, workspace))
        if consent is None or not consent.active:
            return
        sessions = await self._local(partial(self.local.codex_sessions_for_workspace, workspace))
        for codex_session_id in sessions:
            if supervisor.closed or supervisor.has_handle(workspace):
                return
            mapping = self.mapping_loader(codex_session_id, _state=self.state_root)
            if mapping is None:
                continue
            predecessor_writer_id = mapping.yoetz_writer_id
            runtime: TaskRuntime | None = None
            try:
                runtime, mapping = await self._route_observation_mapping(mapping)
                store = self._observation_store(runtime)
                repository = self._advice_semantic_repository(store)
                if repository is None or workspace not in repository.list_pending_workspaces():
                    continue
                if await self._register_advice_semantic_drain(
                    workspace,
                    runtime,
                    legacy_writer_id=predecessor_writer_id,
                    deferred_runtime=runtime,
                ):
                    runtime = None
                return
            except Exception:
                continue
            finally:
                if runtime is not None:
                    release = getattr(self.runtime, "release", None)
                    if release is not None:
                        await release(runtime)

    async def revisit_advice_semantic(self, workspace: str, yoetz_session_id: str) -> None:
        """Rebuild one session's advice once a deferred background review may run (#888).

        Called by the supervisor's revisit timer, never on the hook path. The rebuild re-runs the
        scheduler, which admits the review if the rate limit or backoff has elapsed, defers again
        otherwise, and registers the drain exactly as a hook-driven build would.
        """

        supervisor = self.advice_semantic_supervisor
        if supervisor is None or self.advice_semantic_dispatch is None or supervisor.closed:
            return
        consent = await self._local(partial(self.local.consent_for, workspace))
        if consent is None or not consent.active:
            return
        sessions = await self._local(partial(self.local.codex_sessions_for_workspace, workspace))
        for codex_session_id in sessions:
            mapping = self.mapping_loader(codex_session_id, _state=self.state_root)
            if mapping is None or mapping.yoetz_session_id != yoetz_session_id:
                continue
            predecessor_writer_id = mapping.yoetz_writer_id
            runtime: TaskRuntime | None = None
            try:
                runtime, mapping = await self._route_observation_mapping(mapping)
                store = self._observation_store(runtime)
                await self._run_advice(
                    workspace, runtime, store, legacy_writer_id=predecessor_writer_id
                )
            except Exception as exc:  # noqa: BLE001 - the next hook build retries naturally
                record_unexpected_exception_without_raising(
                    exc,
                    component="application.observation_coordinator",
                    operation="advice_semantic_revisit_failed",
                )
            finally:
                if runtime is not None:
                    release = getattr(self.runtime, "release", None)
                    if release is not None:
                        await release(runtime)
            return

    def _advice_semantic_repository(
        self, store: object
    ) -> ObservationAdviceSemanticRepository | None:
        factory = getattr(store, "advice_semantic_repository", None)
        if not callable(factory):
            return None
        repository = factory()
        return None if repository is None else cast(ObservationAdviceSemanticRepository, repository)

    async def _register_advice_semantic_drain(
        self,
        workspace: str,
        runtime: TaskRuntime,
        *,
        legacy_writer_id: str | None = None,
        session_commitment: str | None = None,
        deferred_runtime: TaskRuntime | None = None,
    ) -> bool:
        """Register (or wake) the workspace's AI-powered advice drain; never dispatch inline.

        Returns True when a new handle now owns ``deferred_runtime`` (or a freshly routed one)
        and will release it on idle. Without a supervisor or dispatch the pending row simply
        stays pending and its coverage gap remains visible.
        """

        supervisor = self.advice_semantic_supervisor
        dispatch = self.advice_semantic_dispatch
        if supervisor is None or dispatch is None or supervisor.closed:
            return False
        if supervisor.has_handle(workspace):
            supervisor.notify(workspace)
            return False
        owned = deferred_runtime
        if owned is None:
            owned = await self._route_observation_runtime(runtime.task_id, runtime.session_id)
        callback_registered = False

        def no_rebind() -> None:
            return

        rebind_callback: Callable[[], None] = no_rebind
        unregister_rebind: Callable[[TaskRuntime, Callable[[], None]], None] | None = None
        try:
            owned_store = self._observation_store(owned)
            repository = self._advice_semantic_repository(owned_store)
            if repository is None:
                if deferred_runtime is None:
                    await self.runtime.release(owned)
                return False

            def now_wire() -> str:
                return timestamp_from_datetime(self.clock.now_utc()).wire

            def lease_expiry() -> str:
                return timestamp_from_datetime(self.clock.now_utc() + timedelta(minutes=2)).wire

            worker = ObservationAdviceSemanticWorker(
                repository=repository,
                dispatch=dispatch,
                service_generation=owned.fence.service_generation,
                lease_owner=owned.fence.service_instance_id,
                now=now_wire,
                lease_expires_at=lease_expiry,
                reconcile_cancelled=self.advice_semantic_cancellation_reconciler,
            )
            bound_runtime = owned

            def rebind_callback() -> None:
                supervisor.request_rebind(workspace)

            register_rebind_obj = getattr(self.runtime, "register_rebind_callback", None)
            unregister_rebind_obj = getattr(self.runtime, "unregister_rebind_callback", None)
            register_rebind = (
                cast(
                    Callable[[TaskRuntime, Callable[[], None]], bool],
                    register_rebind_obj,
                )
                if callable(register_rebind_obj)
                else None
            )
            unregister_rebind = (
                cast(
                    Callable[[TaskRuntime, Callable[[], None]], None],
                    unregister_rebind_obj,
                )
                if callable(unregister_rebind_obj)
                else None
            )

            async def _after() -> None:
                await self._run_advice(
                    workspace,
                    bound_runtime,
                    owned_store,
                    legacy_writer_id=legacy_writer_id,
                    session_commitment=session_commitment,
                )

            async def _release() -> None:
                if callback_registered and unregister_rebind is not None:
                    unregister_rebind(bound_runtime, rebind_callback)
                await self.runtime.release(bound_runtime)

            registered = supervisor.register(
                AdviceSemanticDrainHandle(
                    workspace_commitment=workspace,
                    worker=worker,
                    after_complete=_after,
                    on_idle=_release,
                )
            )
            if not registered:
                if callback_registered and unregister_rebind is not None:
                    unregister_rebind(bound_runtime, rebind_callback)
                if deferred_runtime is None:
                    await self.runtime.release(owned)
                supervisor.notify(workspace)
                return False
            # A waiting foreground start can fire the callback synchronously at registration.
            # Publish the handle first so that eager yield can retire this exact worker.
            if register_rebind is not None:
                try:
                    callback_registered = bool(register_rebind(bound_runtime, rebind_callback))
                except Exception:
                    callback_registered = False
        except BaseException:
            if callback_registered and unregister_rebind is not None:
                unregister_rebind(owned, rebind_callback)
            if deferred_runtime is None:
                await self.runtime.release(owned)
            raise
        supervisor.notify(workspace)
        return True

    def _materialized_event_refs(
        self,
        task_id: str,
        envelope: ObservationEnvelope,
        store: TaskObservationPort | None,
    ) -> tuple[str, ...]:
        key = (task_id, canonical_digest(observation_envelope_to_json(envelope)))
        cached = self._advice_event_ref_cache.pop(key, None)
        if cached is not None:
            self._advice_event_ref_cache[key] = cached
            return cached
        manifest_loader = getattr(store, "load_content_manifest", None)
        recovered: list[ObservationContentManifest] = []
        if callable(manifest_loader):
            for ref in envelope.content_object_refs:
                manifest = cast(ObservationContentManifest | None, manifest_loader(ref))
                if manifest is not None:
                    recovered.append(manifest)
        captured_content = tuple(recovered)
        batch = (
            materialize_observation_envelope(
                envelope,
                task_id=task_id,
                captured_content=captured_content,
            )
            if captured_content
            else materialize_observation_envelope(envelope, task_id=task_id)
        )
        refs = tuple(str(item.draft.event_id) for item in batch.drafts)
        self._advice_event_ref_cache[key] = refs
        while len(self._advice_event_ref_cache) > 4096:
            self._advice_event_ref_cache.pop(next(iter(self._advice_event_ref_cache)))
        return refs

    async def _materialize_advice_findings(
        self,
        runtime: TaskRuntime,
        envelopes: tuple[ObservationEnvelope, ...],
        snapshot: object,
        *,
        store: TaskObservationPort | None = None,
        legacy_writer_id: str | None = None,
    ) -> None:
        from yoetz.domain.observation import AdviceSnapshot

        if type(snapshot) is not AdviceSnapshot or runtime.writer_id is None:
            return
        candidate_items = _materialized_advice_items(snapshot.ranked_items)
        if not candidate_items:
            return
        finding_projection = await runtime.ledger.load_projection(
            runtime.session_id, ProjectionView.CANDIDATE_FINDINGS
        )
        projected_findings: Mapping[FindingId, ProjectionRecord[Finding]] = (
            finding_projection.state.findings
            if finding_projection is not None and type(finding_projection.state) is ProjectionState
            else {}
        )
        candidate_items = tuple(
            item
            for item in candidate_items
            if (
                (existing := projected_findings.get(item.finding_id)) is None
                or existing.payload is None
            )
        )
        if not candidate_items:
            # A readable condition finding already anchors the durable record.
            # Rolling evidence remains current in the observation snapshot and
            # coverage/gap state; appending a revision here would invalidate
            # checks and grow the ledger once per routine envelope.
            return
        refs_by_source: dict[str, set[str]] = {}
        for envelope in envelopes:
            refs_by_source.setdefault(envelope.source_identity, set()).update(
                self._materialized_event_refs(runtime.task_id, envelope, store)
            )
        known_event_ids: set[str] = set()
        lifecycle_ref: str | None = None
        async for record in runtime.ledger.load_events(runtime.session_id):
            known_event_ids.add(str(record.event_id))
            if lifecycle_ref is None and record.schema.name in {
                "session_opened",
                "session_resumed",
            }:
                lifecycle_ref = str(record.event_id)
        projection = await runtime.ledger.load_projection(
            runtime.session_id, ProjectionView.COMPACT
        )
        frontier = Frontier.genesis() if projection is None else projection.frontier
        items: list[tuple[AdviceItem, tuple[str, ...]]] = []
        for item in candidate_items:
            matched_refs = {
                ref
                for source_ref in item.evidence_refs
                for ref in refs_by_source.get(source_ref, ())
                if ref in known_event_ids
            }
            if not matched_refs:
                # A candidate that names no envelope is a standing condition about the session,
                # so anchor it on the session lifecycle event: one stable ref for the life of the
                # condition, which is what lets check and receipt collapse repeats. Where no
                # lifecycle event exists yet, fall back to every observed ref that was actually
                # appended rather than dropping the finding — a finding that silently fails to
                # land is the one outcome this must never produce. Computed draft IDs that
                # never entered the ledger stay out of subject_refs: receipt case construction
                # must not see citations that cannot be closed against the accepted prefix.
                if lifecycle_ref is not None:
                    matched_refs.add(lifecycle_ref)
                else:
                    for observed in refs_by_source.values():
                        matched_refs.update(ref for ref in observed if ref in known_event_ids)
            subject_refs = tuple(sorted(matched_refs, key=str.encode)[:64])
            if not subject_refs:
                continue
            items.append((item, subject_refs))
        if not items:
            return
        request_digest_value = canonical_digest(
            JsonObject(
                {
                    "format": "yoetz.observation-advice-findings/1",
                    "task_id": runtime.task_id,
                    "findings": tuple(
                        {
                            "finding_id": str(item.finding_id),
                            "subject_refs": subject_refs,
                        }
                        for item, subject_refs in items
                    ),
                }
            )
        )
        operation_id = self._stable_operation_id(request_digest_value)
        # The finding event ids and this digest are task-scoped, so the
        # committed operation is resolved task-wide: after a workflow reattach
        # the routed writer is new, but the predecessor session's finding
        # events are already in the ledger (#560).
        existing = await runtime.ledger.lookup_task_operation(runtime.writer_id, operation_id)
        if existing is not None:
            if existing.request_digest != request_digest_value:
                raise PublicOperationError(
                    PublicErrorCode.IDEMPOTENCY_CONFLICT,
                    "Observation advice identity is already committed with other content.",
                    retryable=False,
                )
            return
        if legacy_writer_id is not None and legacy_writer_id != runtime.writer_id:
            legacy_existing = await runtime.ledger.lookup_operation(legacy_writer_id, operation_id)
            if legacy_existing is not None:
                if legacy_existing.request_digest != request_digest_value:
                    raise PublicOperationError(
                        PublicErrorCode.IDEMPOTENCY_CONFLICT,
                        "Observation advice identity is already committed with other content.",
                        retryable=False,
                    )
                return
        entries: list[AppendEntry] = []
        object_refs: list[ObjectRef] = []
        staged_objects: list[StagedObject] = []
        envelope_coverage = coverage_for_channel(PublicationChannel.ENGINE_DERIVED)
        try:
            for item, subject_ref_values in items:
                subject_refs = tuple(event_id(ref) for ref in subject_ref_values)
                kind = _ADVICE_FINDING_KIND_BY_RULE[item.rule_code]
                policy_id = (
                    "work-integrity"
                    if kind
                    in {
                        FindingKind.FAILED_WORK_OMITTED,
                        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
                        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
                        FindingKind.LEDGER_STALE_OR_INCOMPLETE,
                    }
                    else "research-evidence"
                )
                finding = Finding(
                    item.finding_id,
                    kind,
                    FindingOrigin.DETERMINISTIC,
                    FINDING_KIND_TRAITS[kind][0],
                    item.summary,
                    item.detail,
                    subject_refs,
                    policy_id,
                    CURRENT_POLICY_VERSIONS[policy_id],
                    frontier,
                    item.coverage,
                    None,
                )
                schema = EventSchema("finding_recorded", SEMANTIC_EVENT_SCHEMA_VERSION)
                draft = EventDraft(
                    event_id(
                        stable_observation_id(
                            kind=IdKind.EVENT,
                            task_id=runtime.task_id,
                            source_identity=(
                                f"advice-candidate:{item.finding_id}:"
                                f"{canonical_digest(JsonObject({'subject_refs': subject_ref_values}))}"
                            ),
                            mapping_version="obs-advice/1.1.0",
                            role=str(item.finding_id),
                        )
                    ),
                    schema,
                    timestamp_from_datetime(self.clock.now_utc()),
                    (),
                    finding,
                    (),
                    (),
                )
                payload = canonical_encode(encode_payload(finding))
                metadata = ObjectMetadata(
                    ObjectKind.EVENT_PAYLOAD,
                    media_type_for(schema.name),
                    runtime.task_id,
                    self.clock.now_utc(),
                )
                staged = await runtime.objects.stage(
                    ObjectSource(data=payload, declared_size=len(payload)), metadata
                )
                staged_objects.append(staged)
                ref = await runtime.objects.finalize(staged)
                object_refs.append(ref)
                entries.append(
                    AppendEntry(
                        draft,
                        observation_author(),
                        ref,
                        ref.commitment,
                        metadata.media_type,
                        ref.plaintext_size,
                        PublicationChannel.ENGINE_DERIVED,
                        envelope_coverage,
                        "projected",
                    )
                )
            command = AppendCommand(
                runtime.task_id,
                runtime.session_id,
                runtime.writer_id,
                operation_id,
                OperationKind.PUBLISH_WORK,
                request_digest_value,
                None,
                tuple(entries),
            )
            mutation = PreparedMutation(
                command.writer_id,
                command.operation_id,
                command.request_digest,
                command.expected_frontier,
                tuple(object_refs),
                command,
            )
        except BaseException:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise
        try:
            await run_prepared_append(runtime.ledger, mutation)
        except PreSubmissionCancelled:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.observation_coordinator",
                operation="observation_object_abandon_failed",
                request_id=operation_id,
            )
            raise
