"""Daemon-private production ready-application composition."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import contextvars
import hashlib
import inspect
import io
import os
import platform
import sys
import threading
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Final, Literal, Protocol, cast

import apsw

import yoetz.adapters.sqlite.connection as connection_module
import yoetz.adapters.sqlite.recovery as recovery_module
from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.adapters.importers.codex_plan import CodexImportPlans
from yoetz.adapters.integrations.hook_spool import (
    DEFAULT_HOOK_SPOOL_CLAIM_LIMIT,
    HookSpool,
)
from yoetz.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationStoreLockEvent,
    observation_store_lock_deadline,
    set_observation_store_lock_reporter,
    set_observation_store_lock_role,
)
from yoetz.adapters.integrations.observation_task_pending import session_pending_row_identities
from yoetz.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from yoetz.adapters.privacy.catalog import CatalogPrivacyAudit, CatalogPrivacyPolicyStore
from yoetz.adapters.privacy.gateway import PolicyEnforcingOutboundGateway
from yoetz.adapters.privacy.local_enforcer import (
    EGRESS_BYTES_PER_TOKEN_ESTIMATE,
    LocalPrivacyEnforcer,
)
from yoetz.adapters.privacy.provenance import LedgerAuthorshipProvenanceResolver
from yoetz.adapters.providers.codex_app_server import (
    CodexAppServerProfile,
    codex_binding_from_config,
    codex_code_mode_host_path,
)
from yoetz.adapters.providers.codex_evaluator_runtime import diagnose_codex_binding
from yoetz.adapters.providers.factory import external_factory_builders_from_config
from yoetz.adapters.providers.local_model import InstalledLocalModelProfileRegistry
from yoetz.adapters.providers.openai_responses_factory import provider_binding_from_config
from yoetz.adapters.runtime import RuntimeAdapterFactories, open_local_bundle_runtime
from yoetz.adapters.sqlite.connection import (
    SqliteWriterThread,
    open_catalog_writer,
    open_read_only,
    open_writer,
    verify_schema_identity,
)
from yoetz.adapters.sqlite.host_lineage import SqliteHostLineageRegistry
from yoetz.adapters.sqlite.importer import SqliteImporter
from yoetz.adapters.sqlite.lineage_catalog import SqliteLineageStore
from yoetz.adapters.sqlite.migrations import (
    CATALOG_MIGRATIONS,
    initialize_bundle,
    initialize_catalog,
    run_migrations,
)
from yoetz.adapters.sqlite.project_operations import SqliteProjectOperationJournal
from yoetz.adapters.sqlite.repository import SqliteLedger
from yoetz.adapters.sqlite.start_catalog import SqliteStartCatalog
from yoetz.application.check import SEMANTIC_EVALUATION_GAPS, FinalSemanticEvaluation
from yoetz.application.check_change import (
    CheckChangeOutcome,
    capture_check_time_change,
    check_change_shown_files,
    check_time_change_selected,
    declared_output_paths,
    recover_check_time_change,
    task_input_paths,
)
from yoetz.application.coordination import (
    EncryptedCoordinationDetailStore,
    build_coordination_runtime,
)
from yoetz.application.egress import (
    PrivacyCoordinator,
    RepositoryGrantAdmission,
    SemanticEgressAttemptUnknown,
    SemanticEgressAwaitingHuman,
    SemanticEgressBlocked,
    SemanticEgressProviderOutcome,
    SemanticEgressSuccess,
    semantic_policy_refusal,
)
from yoetz.application.lineage import (
    LineageConfig,
    LineageCoordinator,
    LineageProjectAdmission,
)
from yoetz.application.lineage_coordinator import (
    LineageManifestCoordinator,
    LineageSourceGate,
    PrivacyLineageSourceGate,
    authorize_recorded_lineage,
)
from yoetz.application.lineage_recovery import (
    observed_activity_renewal,
    observed_host_session_binding,
)
from yoetz.application.missing_for_assessment import (
    ReviewFollowUp,
    check_change_binary_paths,
    check_change_text_paths,
    unsuppliable_missing_kinds,
)
from yoetz.application.observation_advice import (
    ObservationAdviceContextBuilder,
    stable_advice_finding_id,
)
from yoetz.application.observation_advice_semantic import (
    ObservationAdviceSemanticAttempt,
    ObservationAdviceSemanticOutcome,
    ObservationAdviceSemanticScheduler,
    ObservationAdviceSemanticSupervisor,
    reconcile_cancelled_advice_request,
)
from yoetz.application.observation_control import build_observation_support_handlers
from yoetz.application.observation_coordinator import ObservationCoordinator
from yoetz.application.observation_drain import (
    DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS,
    ObservationDrainSummary,
    ObservationOutboxSweeper,
)
from yoetz.application.observation_verification import ObservationVerificationSupervisor
from yoetz.application.privacy_control import build_privacy_support_handlers
from yoetz.application.privacy_policy import PrivacyPolicyApplication
from yoetz.application.projects import (
    ProjectApplication,
    ProjectCatalogPort,
    ProjectCommandError,
    ProjectObjectStoreLease,
    SourceConsentRevocationPlan,
    build_project_support_handlers,
    build_routed_project_text_store,
)
from yoetz.application.recommendations import evaluate_recommendation_context, refresh_pending
from yoetz.application.semantic_attempts import (
    SemanticAttemptAccounting,
    SemanticEndpointPlan,
    SemanticFallbackPlan,
    attempt_accounting_from_rows,
    run_durable_semantic_attempts,
    status_for_semantic_reason,
)
from yoetz.application.semantic_case import (
    CHECK_TIME_CHANGE_ITEM_PREFIX,
    MAX_CAPTURED_SEMANTIC_CONTENT_PARTS,
    MAX_CAPTURED_SEMANTIC_INPUT_BYTES,
    CheckTimeChange,
    LineageSemanticCapacityExceeded,
    SemanticCaseCapacityExceeded,
    SemanticCaseTooLarge,
    SemanticPacketView,
    bounded_catalog_item_ids,
    build_semantic_case,
    captured_edit_paths,
    carries_task_inputs,
    check_time_change_bytes_carried,
    check_time_change_sections_carried,
    current_section_parts,
    follow_up_new_parts,
    semantic_case_packet_view,
    semantic_case_to_candidate_context,
    sent_excerpt_content_refs,
    sent_excerpt_parts,
    sent_ledger_refs,
    withheld_excerpt_content_refs,
)
from yoetz.application.semantic_content import (
    edit_capture_evidence_count,
    resolve_captured_semantic_content,
)
from yoetz.application.service import (
    ControlProjectionBinding,
    ReadyApplicationFactory,
    ServiceReadyContext,
    VerificationPolicy,
)
from yoetz.config.models import (
    ExternalRuntimeProfileConfig,
    ProviderProfileConfig,
    YoetzConfig,
    background_advice_setting,
    fallback_external_endpoint,
    primary_external_endpoint,
)
from yoetz.config.paths import ensure_owner_only_dir, verify_private_local_bundle
from yoetz.config.privacy import safe_privacy_bootstrap, seed_policy_if_absent
from yoetz.domain.coordination import (
    CoordinationError,
    CoordinationErrorCode,
    LineageAcceptance,
    LineageOrigin,
    ProjectTextRef,
    ProjectTextStore,
    WorkState,
)
from yoetz.domain.events import CheckChangeShownFiles, RuntimeProfile, SessionOpenedPayload
from yoetz.domain.findings import (
    Finding,
    SemanticDispatchKind,
    SemanticFailureClass,
    SemanticFallbackOrigin,
    SemanticProvenance,
    semantic_provenance_to_json,
)
from yoetz.domain.host_lineage import HostLineageHost
from yoetz.domain.observation import (
    ObservationCaptureBacklog,
    ObservationCaptureTicket,
    observation_capture_ticket_id,
)
from yoetz.domain.privacy import (
    OBSERVATION_ADVICE_PACKET_ITEM_ID,
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    ChannelPolicy,
    DataCategory,
    DataClass,
    EgressChannel,
    LocalDisclosureSink,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.receipts import (
    SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
    SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP,
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    SEMANTIC_REVIEW_VALUE_REDACTED_GAP,
    PolicyVersionEntry,
    ReceiptVersionSlice,
    SchemaVersionEntry,
)
from yoetz.domain.task_statement import (
    review_selection_for_delivery,
    specification_preflight,
)
from yoetz.domain.values import (
    Frontier,
    JsonObject,
    disclosure_continuation,
    format_rfc3339_millis,
    parse_rfc3339_millis,
    repository_grant_continuation,
    review_input_continuation,
    task_id,
    timestamp_from_datetime,
    validate_commitment,
)
from yoetz.domain.values import (
    JsonValue as DomainJsonValue,
)
from yoetz.kernel.lineage import LineageEvaluation
from yoetz.kernel.policies.observation_advice import ObservationCompositionFact
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import register_command_identity_key
from yoetz.kernel.test_edit_visibility import preexisting_test_edits
from yoetz.observability.logging import (
    record_bounded_counts_without_raising,
    record_bounded_event_without_raising,
    record_unexpected_exception_without_raising,
)
from yoetz.observability.semantic_context import (
    SemanticProgressSink,
    report_semantic_progress,
    semantic_check_request,
    semantic_progress_sink,
)
from yoetz.ports.change_capture import ChangeCapturePort, current_check_workspace_source
from yoetz.ports.clock import ClockPort
from yoetz.ports.control import ControlError, ControlMethod
from yoetz.ports.diagnostics import (
    DiagnosticsPort,
    RuntimeCapability,
    StartupCheckArea,
    StartupCheckOutcome,
    StartupCheckResult,
)
from yoetz.ports.importer import ImporterPort
from yoetz.ports.keys import (
    LINEAGE_ATTACH_MAC_DOMAIN,
    PROJECT_OPERATION_MAC_DOMAIN,
    BundleKeys,
    MacKeyHandle,
    MacKeyPurpose,
)
from yoetz.ports.ledger import (
    FrozenCase,
    LedgerPort,
    SemanticAttemptHandle,
    SemanticJobRecord,
)
from yoetz.ports.maintenance import PrivacyAuditBackupSnapshot
from yoetz.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
    ObjectStorePort,
    StagedObject,
)
from yoetz.ports.observation import TaskObservationPort
from yoetz.ports.privacy import HumanAuthorityCapability, PrivacyAuditObjectRoots
from yoetz.ports.runtime import (
    BundleRuntimePort,
    OwnershipFence,
    RouteAccess,
    RouteCommand,
    ServiceRuntimeContext,
    StartCompletionEvidence,
    StartMilestone,
    StartMilestoneExpectation,
    TaskRuntime,
)
from yoetz.ports.secret_memory import (
    ProviderAttemptAuthBinding,
    ProviderCredentialHandle,
    SecretMemoryPort,
)
from yoetz.ports.semantic import (
    Deadline,
    SemanticCase,
    SemanticResultInvalid,
    SemanticResultLate,
    SemanticResultRefused,
    SemanticResultTimeout,
    SemanticResultUnavailable,
)
from yoetz.ports.semantic_budget import (
    LEGACY_SEMANTIC_BUDGET_PROFILE,
    SemanticBudgetProfile,
    enter_semantic_budget_profile,
    exit_semantic_budget_profile,
    parse_semantic_budget_profile,
    select_semantic_budget_profile,
    semantic_budget_profile_scope,
)
from yoetz.ports.start_catalog import (
    WORKSPACE_REF_DOMAIN,
    StartCatalogPort,
    StartIdentityInput,
    TaskRoute,
    TaskRouteState,
)
from yoetz.protocol.canonical import JsonValue as CanonicalJsonValue
from yoetz.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, new_id, validate_id, validate_opaque_item_id
from yoetz.protocol.models import (
    SemanticProgressPhase,
    SemanticReason,
    SemanticStatus,
    validate_semantic_provenance_binding,
)
from yoetz.protocol.policy_packs import (
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    current_policy_pack,
)
from yoetz.protocol.redacted_values import SemanticRedactedValue, semantic_redacted_values_from_wire
from yoetz.service.bundle_upgrade import (
    BUNDLE_UPGRADE_SOURCE_VERSION,
    BUNDLE_UPGRADE_SOURCE_VERSIONS,
    BUNDLE_UPGRADE_TARGET_VERSION,
    BackupEvidence,
    BundleIntegrity,
    BundleUpgradeCoordinator,
    BundleUpgradeEffects,
    BundleUpgradeError,
    BundleUpgradeReason,
    BundleUpgradeTarget,
    capture_sqlite_integrity,
)
from yoetz.service.bundle_upgrade_effects import BundleUpgradeFencedLedger
from yoetz.service.import_publication_authority import ImportPublicationAuthority
from yoetz.service.project_coordination_authority import ProjectCoordinationGrantAuthority
from yoetz.service.semantic_attention import SemanticAttentionTracker
from yoetz.service.semantic_ceiling import (
    channel_admission,
    channel_prepared_limit,
    plan_under_channel_ceiling,
    with_ceiling_planning_gap,
)
from yoetz.service.vault import ProviderCredentialBinding, provider_credential_profile_binding
from yoetz.version import build_version_manifest, version_manifest_json

__all__ = [
    "IdPort",
    "build_local_privacy_enforcer",
    "build_privacy_coordinator",
    "build_ready_application_factory",
    "build_runtime_adapter_factories",
    "open_ready_catalog",
    "provide_service_ready_context",
    "SubscriptionReadinessMemo",
    "subscription_runtime_structurally_ready",
]

_CATALOG_NAME = "catalog.sqlite3"
_LEDGER_NAME = "ledger.sqlite3"
_ZERO_DIGEST = "sha256:" + "0" * 64
_LEGACY_HOOK_SPOOL_BATCH_LIMIT: Final = DEFAULT_HOOK_SPOOL_CLAIM_LIMIT
# The egress purpose every background advice dispatch carries; admission judges the same one.
_ADVICE_SEMANTIC_PURPOSE: Final = "semantic-review"


def _admits_llm_inference(policy: PrivacyPolicy) -> bool:
    """Whether a privacy policy permits network egress on the LLM-inference channel."""

    return policy.network_egress_permitted and any(
        channel.channel is EgressChannel.LLM_INFERENCE and channel.enabled
        for channel in policy.channel_policies
    )


class _Lifecycle(Protocol):
    @property
    def instance(self) -> object: ...

    def assert_singleton_held(self) -> None: ...


class _PrivacyRootsStore(Protocol):
    async def live_object_roots(
        self, task_id: str, route_identity_digest: str
    ) -> PrivacyAuditObjectRoots: ...


class _Vault(Protocol):
    @property
    def ready(self) -> bool: ...

    @property
    def generation(self) -> int: ...

    @property
    def mode(self) -> object: ...

    async def load_bundle_keys(self, bundle_id: str) -> BundleKeys: ...

    async def create_bundle_keys(self, bundle_id: str) -> BundleKeys: ...

    def installation_mac_handle(self, purpose: MacKeyPurpose) -> MacKeyHandle: ...

    async def provider_credential(
        self, binding: ProviderAttemptAuthBinding
    ) -> ProviderCredentialHandle: ...

    async def has_provider_credential(self, binding: ProviderCredentialBinding) -> bool: ...


class _Paths(Protocol):
    @property
    def bundle(self) -> Path: ...

    @property
    def state(self) -> Path: ...


class _StartupBundleUpgrade(Protocol):
    """Storage-owned installation upgrade invoked before a generation becomes READY.

    The ready composer owns the ordering guarantee, while the SQLite adapter owns backup,
    migration, replay, and recovery details. Keeping this as one private callback prevents a
    stale task bundle from being silently upgraded by the ordinary lazy runtime opener.
    """

    def __call__(
        self,
        *,
        catalog: SqliteStartCatalog,
        bundle_root: Path,
        installation_id: str,
        service_generation: int,
        vault_generation: int,
        clock: ClockPort,
        ids: IdPort,
        diagnostics: DiagnosticsPort | None,
    ) -> Awaitable[object]: ...


class _SqliteSupportPolicyFactory(Protocol):
    def __call__(
        self,
        *,
        manifest_id: str,
        required_options: frozenset[str],
        denied_options: frozenset[str],
    ) -> object: ...


class IdPort:
    """Production ID port bound to the frozen protocol ID generator."""

    def new(self, kind: IdKind) -> str:
        if type(kind) is not IdKind:
            raise TypeError("id_kind_invalid")
        return new_id(kind)


class _NullDiagnostics:
    def record(self, result: StartupCheckResult) -> None:
        if type(result) is not StartupCheckResult:
            raise TypeError("startup_diagnostic_invalid")


class _CredentialMinter:
    def __init__(self, vault: _Vault) -> None:
        self._vault = vault

    async def mint(self, binding: ProviderAttemptAuthBinding) -> ProviderCredentialHandle:
        return await self._vault.provider_credential(binding)


class _PrivacyContentObjectStore:
    """Process-local content store for privacy disclosure proposals (catalog refs only)."""

    def __init__(self, ids: IdPort) -> None:
        self._ids = ids
        self._objects: dict[str, bytes] = {}
        self._abandoned_ids: set[str] = set()

    async def stage(self, source: ObjectSource, metadata: ObjectMetadata) -> StagedObject:
        if type(source) is not ObjectSource or source.data is None:
            raise ValueError("invalid_object_source")
        object_id = self._ids.new(IdKind.OBJECT)
        digest = "sha256:" + hashlib.sha256(source.data).hexdigest()
        commitment = "hmac-sha256:" + ("a" * 64)
        return StagedObject(
            object_id,
            len(source.data),
            commitment,
            digest,
            "yoetz-object/1",
            "privacy-audit",
            metadata,
            source.data,
        )

    async def finalize(self, staged: StagedObject) -> ObjectRef:
        if staged.object_id in self._abandoned_ids:
            raise ValueError("abandoned_staged_object")
        handle = staged.staging_handle
        if type(handle) is not bytes:
            raise ValueError("privacy_audit_stage_invalid")
        self._objects[staged.object_id] = handle
        return ObjectRef(
            staged.object_id,
            staged.plaintext_size,
            staged.commitment,
            staged.envelope_digest,
            staged.encryption_format,
            staged.key_slot,
            staged.metadata,
        )

    async def abandon(self, staged: StagedObject) -> None:
        self._objects.pop(staged.object_id, None)
        self._abandoned_ids.add(staged.object_id)


@dataclass(frozen=True, slots=True)
class _BundleInspection:
    route: object
    bundle_root: Path
    ledger_path: Path
    catalog_path: Path
    admitted_writer_ids: frozenset[str]
    fresh_allocation: bool
    recovery_state: object
    recovery_verdict: object


@dataclass(frozen=True, slots=True)
class _ReadyObservationSweep:
    """Callable sweep with an explicit per-row maintenance-gate contract."""

    callback: Callable[[], Awaitable[ObservationDrainSummary]]
    row_gate_bound: bool
    # Lock-free read-only probe the idle sweeper polls for undelivered rows (#887).
    backlog_probe: Callable[[], bool] | None = None
    # Blocking read of one Yoetz session's pending hook row identities, store-lock waits bounded
    # by a ``time.monotonic`` deadline: the optional pre-check wait reads it (issue #1012).
    task_pending_probe: Callable[[str, float], frozenset[str]] | None = None

    async def __call__(self) -> ObservationDrainSummary:
        return await self.callback()


def _task_pending_probe(
    local: LocalObservationStore, state: Path
) -> Callable[[str, float], frozenset[str]]:
    """Read one Yoetz session's pending hook rows across workspaces (issue #1012)."""

    def probe(yoetz_session_id: str, deadline: float) -> frozenset[str]:
        with observation_store_lock_deadline(deadline):
            return session_pending_row_identities(
                local, yoetz_session_id=yoetz_session_id, _state=state
            )

    return probe


def _record_observation_store_lock_event(event: ObservationStoreLockEvent) -> None:
    """Record one payload-free store-lock ownership fact in the diagnostic ring (#689).

    The component names the waiting (or long-holding) role, the reason names the holder's
    role, ``reason_code`` its store phase and ``duration_ms`` how long it had held the lock.
    Every value is a closed role, a code identifier or an integer.
    """

    if event.kind == "timeout" and event.timeout is not None:
        timeout = event.timeout
        record_bounded_counts_without_raising(
            component=f"observation.store_lock.{event.role}",
            operation=f"observation_store_{timeout.scope}_lock_timeout",
            outcome=f"holder_{timeout.holder_role}",
            counts={
                "reason_code": timeout.holder_phase,
                "duration_ms": timeout.holder_held_ms
                if timeout.holder_held_ms is not None
                else timeout.waited_ms,
            },
        )
    elif event.kind == "long_hold" and event.held_ms is not None:
        record_bounded_counts_without_raising(
            component=f"observation.store_lock.{event.role}",
            operation="observation_store_lock_long_hold",
            outcome=f"holder_{event.role}",
            counts={"reason_code": event.phase, "duration_ms": event.held_ms},
        )


def _replay_legacy_hook_spool(state: Path, *, stop: threading.Event | None = None) -> None:
    """Normalize one bounded crash-safe legacy-hook spool pass off the service loop."""

    spool = HookSpool(_state=state)
    from yoetz.cli.observe_hooks import handle_observe

    remaining = _LEGACY_HOOK_SPOOL_BATCH_LIMIT
    for workspace_commitment in spool.pending_workspaces():
        if remaining <= 0 or (stop is not None and stop.is_set()):
            return
        with spool.claim(workspace_commitment, limit=remaining) as records:
            for record in records:
                handle_observe(
                    event_name=record.event_name,
                    stdin_bytes=canonical_encode(cast(DomainJsonValue, record.payload)),
                    stdout=io.BytesIO(),
                    _state=state,
                    skip_service=True,
                    _workspace_commitment=workspace_commitment,
                )
        # Invalid structural lines are consumed too, even though they produce no record. Count
        # an empty batch as one unit so malformed workspaces cannot make this pass unbounded.
        remaining -= max(1, len(records))
        # A claim commits its cursor for the complete bounded batch only after this context exits.
        # Stop between claims so generation close cannot leave a partially committed batch.
        if stop is not None and stop.is_set():
            return


class _LegacyHookSpoolForwarder:
    """Own one serialized spool worker for the lifetime of a READY generation.

    The spool claim renames a file and the local hook adapter opens its own short-lived state
    handles. One replay pass claims at most one bounded batch. A cancelled await therefore cannot
    safely start a second claim until the first worker has finished; retaining the future also lets
    the next maintenance pass join that worker. ``close`` asks the worker to stop between claims
    during generation teardown but lets its active batch finish its owned local writes.
    """

    def __init__(self, state: Path) -> None:
        self._state = state
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="yoetz-hook-spool")
        self._stop = threading.Event()
        self._future: asyncio.Future[None] | None = None
        self._closed = False

    async def replay(self) -> None:
        if self._closed:
            return
        future = self._future
        if future is None:
            future = asyncio.get_running_loop().run_in_executor(
                self._executor,
                partial(_replay_legacy_hook_spool, self._state, stop=self._stop),
            )
            self._future = future
        elif future.done():
            # Propagate the prior worker's failure before allowing another pass to begin.  A
            # persistent spool error must remain observable and must not be converted into a
            # false successful drain merely because a fresh worker was started.
            self._future = None
            future.result()
            future = asyncio.get_running_loop().run_in_executor(
                self._executor,
                partial(_replay_legacy_hook_spool, self._state, stop=self._stop),
            )
            self._future = future
        try:
            # wait() leaves its input future running when this caller is cancelled. Unlike
            # shield(), it does not report a retained worker's late exception as unhandled
            # before the next pass can observe that exception (Python 3.14).
            await asyncio.wait((future,))
            future.result()
        except asyncio.CancelledError:
            # The worker still owns its claim. Keep it joinable by the next pass.
            raise
        except BaseException:
            if self._future is future:
                self._future = None
            raise
        else:
            if self._future is future:
                self._future = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        future = self._future
        if future is not None:

            def observe_closed_worker(done: asyncio.Future[None]) -> None:
                if done.cancelled():
                    return
                error = done.exception()
                if isinstance(error, Exception):
                    record_unexpected_exception_without_raising(
                        error,
                        component="service.ready_composition",
                        operation="legacy_hook_spool_replay_failed",
                    )

            future.add_done_callback(observe_closed_worker)
        self._executor.shutdown(wait=False, cancel_futures=True)


async def _run_blocking_joined[ResultT](
    call: Callable[[], ResultT],
    *,
    operation: str,
    cleanup_result: Callable[[ResultT], None] | None = None,
) -> ResultT:
    """Run a side-effecting local operation off-loop and join it before cancellation returns."""

    worker = asyncio.create_task(asyncio.to_thread(call))
    try:
        await asyncio.wait((worker,))
        return worker.result()
    except asyncio.CancelledError:
        # ``asyncio.wait`` does not cancel its input.  Provisioning may have created a bundle or
        # opened a writer before the caller's deadline, so do not release the route/gate while
        # that worker can still mutate the same path.  Preserve the caller's cancellation after
        # the worker has been joined, recording a bounded identity if the worker failed late.
        while not worker.done():
            try:
                await asyncio.wait((worker,))
            except asyncio.CancelledError:
                # A second deadline/caller cancellation must not release the route while the
                # side-effecting worker is still active. Keep joining until it reaches a terminal
                # state, then propagate the original cancellation below.
                continue
        try:
            result = worker.result()
        except BaseException as worker_error:
            if not isinstance(worker_error, asyncio.CancelledError):
                record_unexpected_exception_without_raising(
                    worker_error,
                    component="service.ready_composition",
                    operation=operation,
                )
        else:
            if cleanup_result is not None:
                try:
                    cleanup_result(result)
                except BaseException as cleanup_error:
                    record_unexpected_exception_without_raising(
                        cleanup_error,
                        component="service.ready_composition",
                        operation=f"{operation}_cleanup_failed",
                    )
        raise


def _install_sqlite_support_policy() -> None:
    db = apsw.Connection(":memory:")
    try:
        raw_options: object = db.pragma("compile_options")
    finally:
        db.close(force=True)
    if type(raw_options) is not list:
        raise RuntimeError("sqlite_compile_options_invalid")
    raw_option_items = cast(list[object], raw_options)
    if any(type(item) is not str for item in raw_option_items):
        raise RuntimeError("sqlite_compile_options_invalid")
    options = frozenset(cast(list[str], raw_option_items))
    factory = cast(_SqliteSupportPolicyFactory, getattr(connection_module, "_SqliteSupportPolicy"))
    installer = cast(
        Callable[[object | None], None], getattr(connection_module, "_install_support_policy")
    )
    policy = factory(
        manifest_id=build_version_manifest().resource_manifest_digest,
        required_options=options,
        denied_options=frozenset({"OMIT_FOREIGN_KEY", "OMIT_WAL", "THREADSAFE=0"}),
    )
    installer(policy)


def _install_recovery_persistence(persistence: object) -> None:
    installer = cast(
        Callable[[object | None], None],
        getattr(recovery_module, "_install_recovery_persistence"),
    )
    installer(persistence)


def _open_recovery_writer(path: Path) -> apsw.Connection:
    opener = cast(
        Callable[[Path], apsw.Connection], getattr(connection_module, "_open_recovery_writer")
    )
    return opener(path)


def _open_catalog_migration_writer(path: Path) -> apsw.Connection:
    opener = cast(
        Callable[[Path], apsw.Connection],
        getattr(connection_module, "_open_catalog_migration_writer"),
    )
    return opener(path)


def _nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")


def _close_db(db: apsw.Connection | None) -> None:
    if db is None:
        return
    try:
        db.close(force=True)
    except Exception:
        return


def _catalog_path(paths: _Paths) -> Path:
    return paths.bundle / _CATALOG_NAME


def _safe_bundle_root(base: Path, relpath: str, task_id: str) -> Path:
    validate_id(IdKind.TASK, task_id)
    if type(relpath) is not str:
        raise ValueError("bundle_relpath_invalid")
    parts = Path(relpath).parts
    if parts != ("tasks", task_id):
        raise ValueError("bundle_relpath_invalid")
    root = (base / relpath).resolve(strict=False)
    if root.parent != (base / "tasks").resolve(strict=False):
        raise ValueError("bundle_relpath_invalid")
    return root


def _bundle_upgrade_route_identity(route: TaskRoute) -> tuple[str | int, ...]:
    """Return the catalog facts that must stay fixed for startup migration."""

    return (
        route.task_id,
        route.session_id,
        route.bundle_relpath,
        route.route_generation,
        route.route_identity_digest,
        route.state.value,
    )


def _bundle_upgrade_active_route_identity(
    routes: tuple[TaskRoute, ...],
) -> tuple[tuple[str | int, ...], ...]:
    """Sort the active route inventory for deterministic pre/post migration comparison."""

    return tuple(
        sorted(
            (
                _bundle_upgrade_route_identity(route)
                for route in routes
                if route.state is TaskRouteState.ACTIVE
            ),
            key=lambda item: cast(str, item[0]).encode("ascii"),
        )
    )


def _bundle_upgrade_schema_and_frontier(path: Path) -> tuple[int, Frontier]:
    """Read only the event tail needed to bind a target plan.

    ``open_read_only`` intentionally permits inspection of a schema newer than this binary so
    the coordinator can report ``schema_newer_than_binary``.  Reading the tail here therefore
    must not call ``verify_schema_identity`` a second time: unsupported schemas still need a
    deterministic target binding, while missing/invalid event tables are diagnosed by the
    coordinator's full inspection pass.
    """

    db: apsw.Connection | None = None
    try:
        db = open_read_only(path)
        row = db.execute(
            "SELECT ingestion_seq, entry_digest FROM events ORDER BY ingestion_seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            frontier = Frontier.genesis()
        elif len(row) != 2 or type(row[0]) is not int or type(row[1]) is not str:
            frontier = Frontier.genesis()
        else:
            frontier = Frontier(row[0], row[1])
        version_row = db.execute("PRAGMA user_version").fetchone()
        version = version_row[0] if version_row is not None and type(version_row[0]) is int else 0
        return version, frontier
    except connection_module.StorageUnsafeError as exc:
        if exc.reason_code == "database_missing":
            raise BundleUpgradeError(BundleUpgradeReason.BUNDLE_MISSING, False) from exc
        raise BundleUpgradeError(
            {
                "schema_newer_than_binary": BundleUpgradeReason.SCHEMA_NEWER_THAN_BINARY,
                "schema_metadata_disagrees": BundleUpgradeReason.SCHEMA_METADATA_DISAGREES,
            }.get(exc.reason_code, BundleUpgradeReason.BUNDLE_MISSING),
            False,
        ) from exc
    except apsw.Error, OSError:
        return 0, Frontier.genesis()
    finally:
        _close_db(db)


def _bundle_upgrade_has_pending(catalog: apsw.Connection, installation_id: str, task: str) -> bool:
    """Return whether a v13 route still needs the durable coordinator's full resume proof."""

    try:
        rows = catalog.execute(
            "SELECT state FROM maintenance_operations "
            "WHERE installation_id=? AND task_id=? AND kind='migration' "
            "AND requested_target_version=? ORDER BY created_at DESC LIMIT 2",
            (installation_id, task, "13"),
        ).fetchall()
    except apsw.Error:
        # A missing/corrupt maintenance table must take the conservative path.  The coordinator
        # will then emit its typed schema/operation diagnosis rather than skipping a possibly
        # interrupted migration on the basis of an inventory shortcut.
        return True
    return any(len(row) == 1 and row[0] in {"pending", "quarantined"} for row in rows)


def _record_unsupported_bundle_route(
    diagnostics: DiagnosticsPort | None,
    *,
    route: TaskRoute,
    schema_version: int,
    clock: ClockPort,
) -> None:
    """Report one legacy route while keeping unrelated routes eligible for startup.

    Bundle migrations are deliberately bounded to the v12 source schema.  A dormant v9-v11
    route therefore remains unavailable and untouched, while a current or v12 route can still
    bring the installation READY.  The route identity digest is the safe join key: it binds the
    recovery fact to the catalog route without exposing task titles or paths in diagnostics.
    """

    if diagnostics is None:
        return
    diagnostics.record(
        StartupCheckResult(
            "service.bundle_upgrade.route",
            StartupCheckArea.SQLITE_SCHEMA,
            StartupCheckOutcome.DEGRADED,
            BundleUpgradeReason.SCHEMA_UPGRADE_PATH_UNKNOWN.value,
            frozenset(),
            {
                "route_identity_digest": route.route_identity_digest,
                "schema_version": schema_version,
            },
            clock.now_utc(),
        )
    )


class _BundleUpgradeReplayLedger:
    """Adapt the normal fenced SQLite ledger to the effects replay contract."""

    def __init__(self, ledger: SqliteLedger, db: apsw.Connection) -> None:
        self._ledger = ledger
        self._db = db

    async def _join_recovery_after_cancellation(self) -> None:
        """Join SqliteLedger's shielded recovery task before its fenced connection is closed."""

        recovery_task_value = getattr(self._ledger, "_recovery_task", None)
        if not isinstance(recovery_task_value, asyncio.Task):
            return
        recovery_task = cast(asyncio.Task[object], recovery_task_value)
        while not recovery_task.done():
            try:
                # ``wait`` observes completion without creating a shield wrapper whose late
                # exception can be reported as unhandled after the caller's cancellation.  The
                # task itself remains uncancelled, so this still joins the recovery that owns the
                # fenced connection before teardown.
                await asyncio.wait((recovery_task,))
            except asyncio.CancelledError:
                # Teardown can deliver a second cancellation while the shielded DB worker is
                # still running. Keep joining until it reaches a terminal state; the caller's
                # original cancellation remains the result of verify_replay below.
                continue
            except BaseException:
                # A recovery task may finish with a storage error while the caller is being
                # cancelled. The exception is observed by ``result`` below, but must not replace
                # the cancellation that caused teardown or let the fenced DB close early.
                continue
        try:
            recovery_task.result()
        except BaseException:
            # Preserve the cancellation that caused teardown. A failed recovery task remains
            # visible through the ledger's next operation/restart, while this method's contract
            # is only to prevent it from touching a connection after the fence is released.
            pass

    async def verify_replay(
        self,
        *,
        target: BundleUpgradeTarget,
        before: BundleIntegrity | None,
        after: BundleIntegrity,
        backup: BackupEvidence,
    ) -> str:
        del before, backup
        if target.task_id != after.task_id:
            raise BundleUpgradeError(
                BundleUpgradeReason.VERIFICATION_FAILED,
                False,
                {"check": "replay_binding"},
            )
        try:
            # ``load_frontier`` joins SqliteLedger's shielded recovery task.  The explicit
            # projection rebuild then records the deterministic replay under the temporary
            # ownership fence before the effects layer compares its digest with ``after``.
            frontier = await self._ledger.load_frontier()
            if frontier != after.frontier:
                raise BundleUpgradeError(
                    BundleUpgradeReason.VERIFICATION_FAILED,
                    False,
                    {"check": "replay_frontier"},
                )
            await self._ledger.rebuild_projection("work")
            integrity = capture_sqlite_integrity(self._db)
        except asyncio.CancelledError:
            await self._join_recovery_after_cancellation()
            raise
        except BundleUpgradeError:
            raise
        except Exception as exc:
            raise BundleUpgradeError(
                BundleUpgradeReason.VERIFICATION_FAILED,
                False,
                {"check": "replay"},
            ) from exc
        if (
            integrity.task_id != target.task_id
            or integrity.frontier != after.frontier
            or integrity.projection_digest != after.projection_digest
        ):
            raise BundleUpgradeError(
                BundleUpgradeReason.VERIFICATION_FAILED,
                False,
                {"check": "replay_digest"},
            )
        return integrity.projection_digest


class _BundleUpgradeNoReplayLedger:
    """Marker yielded while backup snapshots a pre-migration bundle."""

    async def verify_replay(
        self,
        *,
        target: BundleUpgradeTarget,
        before: BundleIntegrity | None,
        after: BundleIntegrity,
        backup: BackupEvidence,
    ) -> str:
        del target, before, after, backup
        raise BundleUpgradeError(
            BundleUpgradeReason.VERIFICATION_FAILED,
            False,
            {"check": "replay_before_schema"},
        )


_PRIVACY_AUDIT_COLUMNS: Final[tuple[str, ...]] = (
    "proposal_id",
    "request_id",
    "originating_workflow_request_id",
    "control_rpc_id",
    "control_method",
    "service_instance_id",
    "service_generation",
    "control_request_commitment",
    "subject_lookup_identity",
    "subject_kind",
    "destination_kind",
    "channel",
    "local_sink",
    "provider_id",
    "model_id",
    "endpoint_profile_id",
    "endpoint_profile_version",
    "purpose",
    "scope_kind",
    "scope_digest",
    "policy_id",
    "policy_version",
    "policy_digest",
    "subject_structural_canonical",
    "task_id",
    "route_identity_digest",
    "content_object_id",
    "content_object_kind",
    "content_plaintext_size",
    "content_commitment",
    "content_envelope_digest",
    "content_encryption_format",
    "content_key_slot",
    "content_media_type",
    "content_created_at",
    "state",
    "consent_source",
    "decision_structural_canonical",
    "decision_commitment",
    "approval_binding_commitment",
    "authorization_id",
    "authorization_structural_canonical",
    "authorization_commitment",
    "dispatch_id",
    "dispatch_started_at",
    "consumed_at",
    "attempt_result_structural_canonical",
    "attempt_result_commitment",
    "receipt_id",
    "receipt_outcome",
    "receipt_reason",
    "receipt_canonical",
    "receipt_digest",
    "receipt_finished_at",
    "audit_store_version",
    "expires_at",
    "created_at",
    "updated_at",
)


def _privacy_snapshot_cell(value: object) -> CanonicalJsonValue:
    """Encode one catalog scalar without allowing raw SQLite bytes into the sidecar."""

    if value is None or type(value) in {bool, int, str}:
        return cast(CanonicalJsonValue, value)
    if type(value) is bytes:
        # Catalog canonical fields are structural and may be needed for later audit restoration.
        # The sidecar remains JSON-only while retaining their exact bytes losslessly.
        return base64.b64encode(value).decode("ascii")
    raise ValueError("privacy_snapshot_scalar_invalid")


def _privacy_snapshot_row(columns: tuple[str, ...], row: tuple[object, ...]) -> JsonObject:
    if len(columns) != len(row):
        raise ValueError("privacy_snapshot_row_invalid")
    values = {
        column: _privacy_snapshot_cell(value) for column, value in zip(columns, row, strict=True)
    }
    return JsonObject(values)


async def _load_privacy_audit_snapshot(
    catalog: apsw.Connection,
    *,
    installation_id: str,
    target: BundleUpgradeTarget,
    roots: PrivacyAuditObjectRoots,
) -> PrivacyAuditBackupSnapshot:
    """Build the existing machine-bound privacy sidecar from the current catalog transaction view."""

    if (
        roots.task_id != target.task_id
        or roots.route_identity_digest != target.route_identity_digest
        or roots.privacy_root_generation != target.privacy_root_generation
        or roots.root_set_digest != target.privacy_root_digest
    ):
        raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, True)
    catalog_version_row = catalog.execute("PRAGMA user_version").fetchone()
    if (
        catalog_version_row is None
        or len(catalog_version_row) != 1
        or type(catalog_version_row[0]) is not int
        or catalog_version_row[0] <= 0
    ):
        raise BundleUpgradeError(
            BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "catalog_version"}
        )
    columns = _PRIVACY_AUDIT_COLUMNS
    rows = catalog.execute(
        "SELECT "
        + ",".join(columns)
        + " FROM privacy_audit_records WHERE task_id=? ORDER BY proposal_id",
        (str(target.task_id),),
    ).fetchall()
    audit_rows: list[JsonObject] = []
    terminal_receipts: list[JsonObject] = []
    for raw in rows:
        row = cast(tuple[object, ...], raw)
        structural = _privacy_snapshot_row(columns, row)
        receipt_id = row[columns.index("receipt_id")]
        if receipt_id is None:
            audit_rows.append(structural)
        elif type(receipt_id) is str:
            receipt_indices = (
                "proposal_id",
                "task_id",
                "receipt_id",
                "receipt_outcome",
                "receipt_reason",
                "receipt_canonical",
                "receipt_digest",
                "receipt_finished_at",
            )
            terminal_receipts.append(
                JsonObject(
                    {
                        column: _privacy_snapshot_cell(row[columns.index(column)])
                        for column in receipt_indices
                    }
                )
            )
        else:
            raise BundleUpgradeError(
                BundleUpgradeReason.VERIFICATION_FAILED,
                False,
                {"check": "privacy_receipt_id"},
            )
    audit_rows.sort(key=lambda item: cast(str, item["proposal_id"]).encode("ascii"))
    terminal_receipts.sort(key=lambda item: cast(str, item["receipt_id"]).encode("ascii"))
    audit_versions = {row[columns.index("audit_store_version")] for row in rows}
    if audit_versions - {1}:
        raise BundleUpgradeError(
            BundleUpgradeReason.VERIFICATION_FAILED,
            False,
            {"check": "audit_store_version"},
        )
    return PrivacyAuditBackupSnapshot(
        origin_installation_id=installation_id,
        origin_task_id=target.task_id,
        catalog_version=str(catalog_version_row[0]),
        audit_store_version="1",
        privacy_root_generation=roots.privacy_root_generation,
        privacy_root_digest=roots.root_set_digest,
        audit_rows=tuple(audit_rows),
        terminal_receipts=tuple(terminal_receipts),
        privacy_audit_objects=roots.object_refs,
    )


async def _bundle_upgrade_targets(
    catalog: SqliteStartCatalog,
    *,
    bundle_root: Path,
    installation_id: str,
    clock: ClockPort,
    diagnostics: DiagnosticsPort | None = None,
) -> tuple[tuple[TaskRoute, ...], tuple[BundleUpgradeTarget, ...]]:
    """Capture every stable active route and its frontier before touching any bundle writer."""

    routes = await catalog.recovery_routes()
    active_identity = _bundle_upgrade_active_route_identity(routes)
    catalog_db = cast(apsw.Connection, getattr(catalog, "_db"))
    catalog_generation = catalog.generation
    privacy_store = cast(
        _PrivacyRootsStore,
        CatalogPrivacyAudit(
            catalog_db,
            cast(ObjectStorePort, _PrivacyContentObjectStore(IdPort())),
            cast(MacKeyHandle, getattr(catalog, "_lookup")),
            clock,
            service_generation=catalog_generation,
        ),
    )
    targets: list[BundleUpgradeTarget] = []
    for route in sorted(
        (item for item in routes if item.state is TaskRouteState.ACTIVE),
        key=lambda item: item.task_id.encode("ascii"),
    ):
        try:
            bundle_path = (
                _safe_bundle_root(
                    bundle_root,
                    route.bundle_relpath,
                    route.task_id,
                )
                / _LEDGER_NAME
            )
            schema_version, frontier = await _run_blocking_joined(
                partial(_bundle_upgrade_schema_and_frontier, bundle_path),
                operation="bundle_upgrade_route_inventory_failed",
            )
            if schema_version < BUNDLE_UPGRADE_SOURCE_VERSION:
                _record_unsupported_bundle_route(
                    diagnostics,
                    route=route,
                    schema_version=schema_version,
                    clock=clock,
                )
                continue
            # Current bundles without a pending upgrade do not need their privacy object set
            # re-hashed merely to prove that startup can skip them.  A stale source or an
            # interrupted target-version operation still gets the exact roots that enter the
            # coordinator's plan digest and CAS checks.
            needs_privacy_roots = schema_version in BUNDLE_UPGRADE_SOURCE_VERSIONS or (
                schema_version == BUNDLE_UPGRADE_TARGET_VERSION
                and _bundle_upgrade_has_pending(catalog_db, installation_id, route.task_id)
            )
            if needs_privacy_roots:
                roots = await privacy_store.live_object_roots(
                    route.task_id,
                    route.route_identity_digest,
                )
                privacy_root_generation = roots.privacy_root_generation
                privacy_root_digest = roots.root_set_digest
            else:
                privacy_root_generation = 0
                privacy_root_digest = _ZERO_DIGEST
            targets.append(
                BundleUpgradeTarget(
                    task_id=task_id(route.task_id),
                    session_id=route.session_id,
                    bundle_path=bundle_path,
                    route_generation=route.route_generation,
                    route_identity_digest=route.route_identity_digest,
                    frontier=frontier,
                    catalog_owner_generation=catalog_generation,
                    privacy_root_generation=privacy_root_generation,
                    privacy_root_digest=privacy_root_digest,
                )
            )
        except BundleUpgradeError:
            raise
        except (apsw.Error, OSError, TypeError, ValueError) as exc:
            raise BundleUpgradeError(
                BundleUpgradeReason.VERIFICATION_FAILED,
                False,
                {"check": "startup_route_inventory"},
            ) from exc
    latest_routes = await catalog.recovery_routes()
    if _bundle_upgrade_active_route_identity(latest_routes) != active_identity:
        raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, True)
    return routes, tuple(targets)


def _bundle_upgrade_effects_factory(
    *,
    bundle_root: Path,
    vault: _Vault,
    installation_id: str,
    secret_memory: SecretMemoryPort,
    ids: IdPort,
    clock: ClockPort,
    version_manifest: JsonObject | None,
    open_temporary_fenced_ledger: Callable[
        [BundleUpgradeTarget], AbstractAsyncContextManager[BundleUpgradeFencedLedger]
    ],
    load_privacy_snapshot: Callable[
        [BundleUpgradeTarget, BundleIntegrity], Awaitable[PrivacyAuditBackupSnapshot]
    ],
) -> BundleUpgradeEffects:
    """Build the storage-backed automatic-upgrade effects only when a stale route is found."""

    # Keep this import lazy.  The common fresh-install path has no task bundle to migrate and must
    # not make startup depend on an optional effects implementation being imported while locked.
    from yoetz.service.bundle_upgrade_effects import SqliteBundleUpgradeEffects

    return SqliteBundleUpgradeEffects(
        backup_root=bundle_root / "backups",
        installation_id=installation_id,
        load_bundle_keys=vault.load_bundle_keys,
        secret_memory=secret_memory,
        ids=ids,
        clock=clock,
        open_temporary_fenced_ledger=open_temporary_fenced_ledger,
        load_privacy_snapshot=load_privacy_snapshot,
        version_manifest=version_manifest,
    )


def _build_default_startup_bundle_upgrade(
    *,
    lifecycle: _Lifecycle,
    vault: _Vault,
    config: YoetzConfig,
    paths: _Paths,
    secret_memory: object,
) -> _StartupBundleUpgrade:
    """Compose the automatic v12->v13 upgrade at the single READY admission boundary."""

    del config  # The schema-only operation deliberately does not vary with user policy.
    startup_lock = asyncio.Lock()
    version_manifest = JsonObject(_version_json())

    async def upgrade(
        *,
        catalog: SqliteStartCatalog,
        bundle_root: Path,
        installation_id: str,
        service_generation: int,
        vault_generation: int,
        clock: ClockPort,
        ids: IdPort,
        diagnostics: DiagnosticsPort | None,
    ) -> object:
        del vault_generation
        catalog_db = cast(apsw.Connection, getattr(catalog, "_db"))
        service_instance_id = cast(str, getattr(lifecycle.instance, "instance_id"))

        def assert_lifecycle_holder() -> None:
            assertion = getattr(lifecycle, "assert_singleton_held", None)
            if not callable(assertion):
                raise BundleUpgradeError(BundleUpgradeReason.HOLDER_REQUIRED, False)
            try:
                assertion()
            except BundleUpgradeError:
                raise
            except Exception as exc:
                raise BundleUpgradeError(BundleUpgradeReason.HOLDER_CONFLICT, True) from exc

        route_snapshot, targets = await _bundle_upgrade_targets(
            catalog,
            bundle_root=bundle_root,
            installation_id=installation_id,
            clock=clock,
            diagnostics=diagnostics,
        )
        if not targets:
            return None
        record_bounded_counts_without_raising(
            component="service.ready_composition",
            operation="bundle_upgrade_startup_progress",
            outcome="upgrade_pending",
            counts={"operation_count": len(targets)},
        )

        # The recovery backend is also used by the temporary replay ledger.  Install it before
        # effects run, after the catalog is current and while this process still owns the
        # singleton.  The effects layer never mutates the bundle during read-only inspection.
        recovery_persistence = _RecoveryPersistence(_catalog_path(paths), clock)
        _install_recovery_persistence(recovery_persistence)

        @contextlib.asynccontextmanager
        async def acquire_exclusive_holder(
            candidates: tuple[BundleUpgradeTarget, ...],
        ) -> AsyncGenerator[None]:
            if type(candidates) is not tuple or not candidates:
                raise BundleUpgradeError(BundleUpgradeReason.HOLDER_REQUIRED, False)
            try:
                assert_lifecycle_holder()
                async with startup_lock:
                    assert_lifecycle_holder()
                    yield
                    assert_lifecycle_holder()
            except BundleUpgradeError:
                raise
            except Exception as exc:
                raise BundleUpgradeError(BundleUpgradeReason.HOLDER_CONFLICT, True) from exc

        @contextlib.asynccontextmanager
        async def temporary_fenced_ledger(
            target: BundleUpgradeTarget,
        ) -> AsyncGenerator[BundleUpgradeFencedLedger]:
            """Open one replay ledger under the current bundle metadata fence, then erase it."""

            assert_lifecycle_holder()
            schema_version, _frontier = await _run_blocking_joined(
                partial(_bundle_upgrade_schema_and_frontier, target.bundle_path),
                operation="bundle_upgrade_replay_inventory_failed",
            )
            if schema_version != BUNDLE_UPGRADE_TARGET_VERSION:
                # The backup effect enters this context before the source v12 schema is migrated.
                # It only needs the service holder fence during that phase; opening the normal
                # runtime writer would correctly reject the stale schema and strand the backup.
                yield _BundleUpgradeNoReplayLedger()
                assert_lifecycle_holder()
                return
            bundle_dir = target.bundle_path.parent
            state = await _run_blocking_joined(
                partial(
                    recovery_persistence.inspect,
                    bundle_dir,
                    catalog_path=_catalog_path(paths),
                    task_id=str(target.task_id),
                    route_generation=target.route_generation,
                    route_identity_digest=target.route_identity_digest,
                ),
                operation="bundle_upgrade_recovery_inventory_failed",
            )
            if type(state) is not recovery_module.RecoveryState:
                raise BundleUpgradeError(BundleUpgradeReason.VERIFICATION_FAILED, False)
            route = TaskRoute(
                task_id=str(target.task_id),
                session_id=target.session_id,
                bundle_relpath=f"tasks/{target.task_id}",
                route_generation=target.route_generation,
                state=TaskRouteState.ACTIVE,
                route_identity_digest=target.route_identity_digest,
            )
            inspection = _BundleInspection(
                route,
                bundle_dir,
                target.bundle_path,
                _catalog_path(paths),
                frozenset(),
                False,
                state,
                recovery_module.validate_recovery_tail(state),
            )
            fence = OwnershipFence(
                service_instance_id=service_instance_id,
                service_generation=service_generation,
                owner_generation=state.owner_generation,
                nonce=state.owner_nonce,
            )
            registrar = cast(
                Callable[[Path, OwnershipFence], None],
                getattr(connection_module, "_register_active_fence"),
            )
            clearer = cast(
                Callable[[Path, OwnershipFence | None], None],
                getattr(connection_module, "_clear_active_fence"),
            )
            db: apsw.Connection | None = None
            registered = False
            try:
                registrar(target.bundle_path, fence)
                registered = True
                db = await _run_blocking_joined(
                    partial(open_writer, target.bundle_path),
                    operation="bundle_upgrade_replay_writer_open_failed",
                    cleanup_result=_close_db,
                )
                keys = await vault.load_bundle_keys(str(target.task_id))
                objects = EncryptedFilesObjectStore(
                    bundle_root=bundle_dir,
                    bundle_keys=keys,
                    secret_memory=secret_memory,  # pyright: ignore[reportArgumentType]
                    id_port=ids,
                    current_root_snapshot=lambda: _root_snapshot(inspection, db, clock, catalog_db),
                )
                ledger = SqliteLedger(
                    db=db,
                    task_id=str(target.task_id),
                    ownership_fence=fence,
                    clock=clock,
                    ids=ids,
                    objects=objects,
                )
                yield _BundleUpgradeReplayLedger(ledger, db)
            except BundleUpgradeError:
                raise
            except Exception as exc:
                raise BundleUpgradeError(BundleUpgradeReason.VERIFICATION_FAILED, False) from exc
            finally:
                primary_error = sys.exc_info()[1]

                def report_holder_loss() -> None:
                    record_bounded_event_without_raising(
                        component="service.ready_composition",
                        operation="bundle_upgrade_holder_lost_during_cleanup",
                        reason="singleton_not_held",
                    )

                _close_db(db)
                if registered:
                    cleanup_error: BaseException | None = None
                    holder_error: BaseException | None = None
                    try:
                        assert_lifecycle_holder()
                    except BaseException as exc:
                        holder_error = exc
                        cleanup_error = exc
                    try:
                        clearer(target.bundle_path, fence)
                    except BaseException as exc:
                        if cleanup_error is None:
                            cleanup_error = exc
                    registered = False
                    if cleanup_error is not None:
                        if holder_error is not None:
                            report_holder_loss()
                        if primary_error is None:
                            raise cleanup_error
                try:
                    assert_lifecycle_holder()
                except BaseException:
                    if primary_error is None:
                        raise
                    report_holder_loss()

        async def privacy_snapshot(
            target: BundleUpgradeTarget, before: BundleIntegrity
        ) -> PrivacyAuditBackupSnapshot:
            if before.task_id != target.task_id or before.frontier != target.frontier:
                raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, True)
            roots_store = cast(
                _PrivacyRootsStore,
                CatalogPrivacyAudit(
                    catalog_db,
                    cast(ObjectStorePort, _PrivacyContentObjectStore(ids)),
                    vault.installation_mac_handle(MacKeyPurpose.PRIVACY_AUDIT),
                    clock,
                    service_generation=service_generation,
                ),
            )
            roots = await roots_store.live_object_roots(
                str(target.task_id),
                target.route_identity_digest,
            )
            return await _load_privacy_audit_snapshot(
                catalog_db,
                installation_id=installation_id,
                target=target,
                roots=roots,
            )

        try:
            effects = _bundle_upgrade_effects_factory(
                bundle_root=bundle_root,
                vault=vault,
                secret_memory=cast(SecretMemoryPort, secret_memory),
                installation_id=installation_id,
                ids=ids,
                clock=clock,
                version_manifest=version_manifest,
                open_temporary_fenced_ledger=temporary_fenced_ledger,
                load_privacy_snapshot=privacy_snapshot,
            )
            coordinator = BundleUpgradeCoordinator(
                catalog=catalog_db,
                installation_id=installation_id,
                service_instance_id=service_instance_id,
                clock=clock,
                effects=effects,
                acquire_exclusive_holder=acquire_exclusive_holder,
                assert_exclusive_holder=assert_lifecycle_holder,
                ids=ids,
            )
            report = await coordinator.run_before_ready(targets)
            record_bounded_counts_without_raising(
                component="service.ready_composition",
                operation="bundle_upgrade_startup_progress",
                outcome="upgrade_complete",
                counts={
                    "operation_count": len(report.migrated) + len(report.already_current),
                },
            )
            latest_routes = await catalog.recovery_routes()
            if _bundle_upgrade_active_route_identity(
                latest_routes
            ) != _bundle_upgrade_active_route_identity(route_snapshot):
                raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, True)
            return report
        except BundleUpgradeError as exc:
            record_bounded_event_without_raising(
                component="service.ready_composition",
                operation="bundle_upgrade_startup_failed",
                reason=exc.reason.value,
            )
            if diagnostics is not None:
                diagnostics.record(
                    StartupCheckResult(
                        "service.bundle_upgrade",
                        StartupCheckArea.SQLITE_SCHEMA,
                        (
                            StartupCheckOutcome.DEGRADED
                            if exc.retryable
                            else StartupCheckOutcome.BLOCKED
                        ),
                        exc.reason.value,
                        frozenset(),
                        {},
                        clock.now_utc(),
                    )
                )
            raise

    return upgrade


def _seed_catalog_meta(
    db: apsw.Connection, *, installation_id: str, service_generation: int
) -> None:
    validate_id(IdKind.INSTALLATION, installation_id)
    if type(service_generation) is not int or service_generation <= 0:
        raise ValueError("service_generation_invalid")
    with db:
        existing = db.execute(
            "SELECT value FROM catalog_meta WHERE key = 'installation_id'"
        ).fetchone()
        if existing is not None and existing != (installation_id,):
            raise ValueError("catalog_installation_mismatch")
        db.execute(
            "INSERT INTO catalog_meta(key, value) VALUES ('installation_id', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (installation_id,),
        )
        db.execute(
            "INSERT INTO catalog_meta(key, value) VALUES ('owner_generation', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(service_generation),),
        )


async def open_ready_catalog(
    path: Path,
    *,
    installation_id: str,
    service_generation: int,
    lookup: object,
    clock: ClockPort,
    ids: IdPort,
) -> SqliteStartCatalog:
    """Open, initialize if needed, and generation-bind the ready catalog."""

    _install_sqlite_support_policy()
    try:
        db = open_catalog_writer(path)
    except connection_module.StorageUnsafeError as exc:
        if exc.reason_code != "schema_metadata_disagrees":
            raise
        migration_db = _open_catalog_migration_writer(path)
        try:
            run_migrations(migration_db, CATALOG_MIGRATIONS, maintenance=None)
        finally:
            _close_db(migration_db)
        # Migration DDL never shares a connection with runtime work. Reopen through the ordinary
        # authorizer-guarded path and re-verify the resulting identity below.
        db = open_catalog_writer(path)
    try:
        identity = verify_schema_identity(db)
        if identity.state == "uninitialized":
            initialize_catalog(db)
        elif identity.state != "current":
            raise ValueError("catalog_schema_unsupported")
        _seed_catalog_meta(
            db,
            installation_id=installation_id,
            service_generation=service_generation,
        )
        return SqliteStartCatalog(
            db,
            installation_id=installation_id,
            lookup=lookup,  # pyright: ignore[reportArgumentType]
            clock=clock,
            ids=ids,
        )
    except BaseException:
        _close_db(db)
        raise


class _RecoveryPersistence:
    def __init__(self, catalog_path: Path, clock: ClockPort) -> None:
        self._catalog_path = catalog_path
        self._clock = clock

    def inspect(
        self,
        bundle_root: Path,
        *,
        catalog_path: Path,
        task_id: str,
        route_generation: int,
        route_identity_digest: str,
    ) -> object:
        if catalog_path != self._catalog_path:
            raise ValueError("recovery_catalog_mismatch")
        ledger_path = bundle_root / _LEDGER_NAME
        db = open_read_only(ledger_path)
        catalog = open_read_only(catalog_path)
        try:
            metadata = self._bundle_meta(db)
            if (
                metadata.get("task_id") != task_id
                or metadata.get("route_generation") != str(route_generation)
                or metadata.get("route_identity_digest") != route_identity_digest
            ):
                raise ValueError("recovery_route_mismatch")
            frontier = self._frontier(db)
            privacy_generation, privacy_digest = self._privacy_root(catalog, task_id)
            return recovery_module.RecoveryState(
                bundle_root=bundle_root,
                catalog_path=catalog_path,
                task_id=task_id,
                route_generation=route_generation,
                route_identity_digest=route_identity_digest,
                storage_schema_version=int(metadata.get("storage_schema_version", "0"), 10),
                owner_generation=int(metadata.get("owner_generation", "0"), 10),
                owner_nonce=metadata["owner_nonce"],
                last_verified_frontier=frontier,
                tail_state=recovery_module.RecoveryTailState.CLEAN,
                object_state=recovery_module.RecoveryObjectState.VERIFIED,
                key_state=recovery_module.RecoveryKeyState.READY,
                marker_state=recovery_module.RecoveryMarkerState.ABSENT,
                projection_state=recovery_module.RecoveryProjectionState.CURRENT,
                privacy_root_generation=privacy_generation,
                privacy_root_digest=privacy_digest,
            )
        finally:
            _close_db(catalog)
            _close_db(db)

    def acquire_ownership(
        self,
        state: object,
        *,
        service_instance_id: str,
        service_generation: int,
        owner_nonce: str,
        now: datetime,
    ) -> int:
        if type(state) is not recovery_module.RecoveryState:
            raise ValueError("recovery_value_invalid")
        validate_id(IdKind.SERVICE_INSTANCE, service_instance_id)
        # service_generation remains part of the fence; bundle owner_generation is
        # per-bundle monotonic and independent of the service/catalog generation.
        del service_generation
        format_rfc3339_millis(now)
        db = _open_recovery_writer(state.bundle_root / _LEDGER_NAME)
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                metadata = self._bundle_meta(db)
                if (
                    metadata.get("task_id") != state.task_id
                    or metadata.get("route_generation") != str(state.route_generation)
                    or metadata.get("route_identity_digest") != state.route_identity_digest
                    or metadata.get("owner_generation") != str(state.owner_generation)
                    or metadata.get("owner_nonce") != state.owner_nonce
                ):
                    raise ValueError("recovery_ownership_conflict")
                next_generation = state.owner_generation + 1
                if not self._swap_meta(
                    db, "owner_generation", str(state.owner_generation), str(next_generation)
                ):
                    raise ValueError("recovery_ownership_conflict")
                if not self._swap_meta(db, "owner_nonce", state.owner_nonce, owner_nonce):
                    raise ValueError("recovery_ownership_conflict")
                self._set_meta(db, "updated_at", format_rfc3339_millis(now))
            except BaseException:
                db.execute("ROLLBACK")
                raise
            else:
                db.execute("COMMIT")
            return next_generation
        finally:
            _close_db(db)

    def verify_fence(self, state: object, fence: OwnershipFence) -> None:
        if type(state) is not recovery_module.RecoveryState or type(fence) is not OwnershipFence:
            raise ValueError("recovery_value_invalid")
        db = open_read_only(state.bundle_root / _LEDGER_NAME)
        try:
            metadata = self._bundle_meta(db)
            if (
                metadata.get("owner_generation") != str(fence.owner_generation)
                or metadata.get("owner_nonce") != fence.nonce
                or metadata.get("task_id") != state.task_id
                or metadata.get("route_identity_digest") != state.route_identity_digest
                or metadata.get("route_generation") != str(state.route_generation)
            ):
                raise ValueError("recovery_fence_invalid")
        finally:
            _close_db(db)

    def complete_interrupted(
        self, state: object, fence: OwnershipFence, *, now: datetime
    ) -> object:
        del fence, now
        if type(state) is not recovery_module.RecoveryState:
            raise ValueError("recovery_value_invalid")
        return replace(state, tail_state=recovery_module.RecoveryTailState.CLEAN)

    def rebuild_projection(self, state: object, fence: OwnershipFence, *, now: datetime) -> object:
        del fence, now
        if type(state) is not recovery_module.RecoveryState:
            raise ValueError("recovery_value_invalid")
        return replace(state, projection_state=recovery_module.RecoveryProjectionState.CURRENT)

    def persist_quarantine(
        self,
        state: object,
        reason: object,
        fence: OwnershipFence,
        *,
        now: datetime,
    ) -> None:
        del fence
        if type(state) is not recovery_module.RecoveryState:
            raise ValueError("recovery_value_invalid")
        catalog = open_catalog_writer(state.catalog_path)
        try:
            with catalog:
                catalog.execute(
                    "UPDATE task_routes SET state='quarantined', quarantine_code=?, updated_at=? "
                    "WHERE task_id=? AND active_route_identity_digest=?",
                    (
                        getattr(reason, "value", "recovery_quarantined"),
                        format_rfc3339_millis(now),
                        state.task_id,
                        state.route_identity_digest,
                    ),
                )
        finally:
            _close_db(catalog)

    def activate_restore(
        self, state: object, manifest: object, fence: OwnershipFence, *, now: datetime
    ) -> str:
        del state, manifest, fence, now
        return "provenance_invalid"

    @staticmethod
    def _bundle_meta(db: apsw.Connection) -> dict[str, str]:
        rows = db.execute("SELECT key, value FROM bundle_meta").fetchall()
        if any(len(row) != 2 or type(row[0]) is not str or type(row[1]) is not str for row in rows):
            raise ValueError("bundle_meta_invalid")
        return {cast(str, row[0]): cast(str, row[1]) for row in rows}

    @staticmethod
    def _set_meta(db: apsw.Connection, key: str, value: str) -> None:
        db.execute(
            "INSERT INTO bundle_meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    @staticmethod
    def _swap_meta(db: apsw.Connection, key: str, expected: str, value: str) -> bool:
        db.execute(
            "UPDATE bundle_meta SET value = ? WHERE key = ? AND value = ?",
            (value, key, expected),
        )
        return db.changes() == 1

    @staticmethod
    def _frontier(db: apsw.Connection) -> Frontier:
        row = db.execute(
            "SELECT ingestion_seq, entry_digest FROM events ORDER BY ingestion_seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return Frontier.genesis()
        if len(row) != 2 or type(row[0]) is not int or type(row[1]) is not str:
            raise ValueError("ledger_frontier_invalid")
        return Frontier(row[0], row[1])

    @staticmethod
    def _privacy_root(catalog: apsw.Connection, task_id: str) -> tuple[int, str]:
        row = catalog.execute(
            "SELECT root_generation, root_digest FROM privacy_root_sets WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            return 0, _ZERO_DIGEST
        if len(row) != 2 or type(row[0]) is not int or type(row[1]) is not str:
            raise ValueError("privacy_root_invalid")
        return row[0], row[1]


def _project_text_ref_from_catalog(value: object) -> ProjectTextRef:
    """Decode one canonical catalog pointer without ever resolving its plaintext object."""

    if type(value) is bytes:
        encoded = value
    elif type(value) is str:
        encoded = value.encode("utf-8")
    else:
        raise ValueError("project_text_root_ref_invalid")
    try:
        parsed = strict_json_parse(encoded)
        if not isinstance(parsed, Mapping) or canonical_encode(parsed) != encoded:
            raise ValueError("project_text_root_ref_noncanonical")
        required = {
            "object_id",
            "content_digest",
            "plaintext_size",
            "owner_task_id",
            "route_generation",
        }
        keys = set(parsed)
        if keys not in (required, required | {"envelope_digest"}):
            raise ValueError("project_text_root_ref_shape_invalid")
        route_generation = parsed["route_generation"]
        if type(route_generation) is not str:
            raise ValueError("project_text_root_ref_generation_invalid")
        generation = int(route_generation, 10)
        if str(generation) != route_generation:
            raise ValueError("project_text_root_ref_generation_invalid")
        if type(parsed.get("envelope_digest")) is not str:
            raise ValueError("project_text_root_ref_envelope_invalid")
        return ProjectTextRef(
            object_id=cast(str, parsed["object_id"]),
            content_digest=cast(str, parsed["content_digest"]),
            plaintext_size=cast(int, parsed["plaintext_size"]),
            owner_task_id=cast(str, parsed["owner_task_id"]),
            route_generation=generation,
            envelope_digest=cast(str | None, parsed.get("envelope_digest")),
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("project_text_root_ref_invalid") from exc


async def _root_snapshot(
    inspection: _BundleInspection,
    db: apsw.Connection,
    clock: ClockPort,
    catalog_db: apsw.Connection | None = None,
) -> ObjectRootSnapshot:
    state = cast(recovery_module.RecoveryState, inspection.recovery_state)
    object_ids = {
        row[0]
        for row in db.execute(
            "SELECT object_id FROM objects WHERE state='present' ORDER BY object_id"
        ).fetchall()
        if len(row) == 1 and type(row[0]) is str
    }
    # Project text lives in the owner task's encrypted bundle while its structural pointer is
    # catalog-resident.  Include every pointer owned by this task as a root, including a pointer
    # to a retained route generation.  A catalog ref must not be able to turn into an orphan just
    # because the active bundle's object inventory no longer has a row for that generation.
    if catalog_db is not None:
        project_rows = catalog_db.execute(
            "SELECT title_ref_canonical, description_ref_canonical FROM projects"
        ).fetchall()
        refs: list[object] = []
        for row in project_rows:
            if len(row) != 2:
                raise ValueError("project_text_root_row_invalid")
            refs.extend(row)
        # A response-loss or process crash can leave encrypted project text referenced only by a
        # pending operation row until the catalog effect is replayed. Keep those exact refs rooted
        # across orphan sweeps; otherwise recovery would have to mint a second object (or fail
        # after the original ciphertext was collected). Older catalogs have no journal table, so
        # probe it just like the coordination-detail table below.
        if (
            catalog_db.execute(
                "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='project_operations'"
            ).fetchone()
            is not None
        ):
            for row in catalog_db.execute(
                "SELECT title_ref_canonical, description_ref_canonical FROM project_operations "
                "WHERE title_ref_canonical IS NOT NULL OR description_ref_canonical IS NOT NULL"
            ).fetchall():
                if len(row) != 2:
                    raise ValueError("project_text_root_row_invalid")
                refs.extend(row)
        # Coordination detail pointers use TEXT because the coordination adapter's structural
        # JSON columns are canonical UTF-8.  Older catalogs may predate the table entirely, so
        # probe the schema before reading it rather than turning a valid upgrade into a root
        # capture failure.
        if (
            catalog_db.execute(
                "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='coordination_detections'"
            ).fetchone()
            is not None
        ):
            for row in catalog_db.execute(
                "SELECT detail_ref_json FROM coordination_detections "
                "WHERE detail_ref_json IS NOT NULL"
            ).fetchall():
                if len(row) != 1:
                    raise ValueError("project_text_root_row_invalid")
                refs.append(row[0])
        known_route_generations: dict[str, frozenset[int]] = {}
        for encoded in refs:
            if encoded is None:
                continue
            reference = _project_text_ref_from_catalog(encoded)
            known = known_route_generations.get(reference.owner_task_id)
            if known is None:
                route_rows = catalog_db.execute(
                    "SELECT route_generation FROM task_routes WHERE task_id = ? "
                    "UNION ALL SELECT route_generation FROM retained_task_routes "
                    "WHERE task_id = ? AND state IN ('retained', 'quarantined')",
                    (reference.owner_task_id, reference.owner_task_id),
                ).fetchall()
                known = frozenset(
                    row[0] for row in route_rows if len(row) == 1 and type(row[0]) is int
                )
                known_route_generations[reference.owner_task_id] = known
            if reference.route_generation not in known:
                raise ValueError("project_text_root_route_invalid")
            if reference.owner_task_id == state.task_id:
                object_ids.add(reference.object_id)
    object_ids = set(object_ids)
    ordered_object_ids = tuple(sorted(object_ids, key=str.encode))
    object_digest = canonical_digest(ordered_object_ids)
    return ObjectRootSnapshot(
        task_id=state.task_id,
        route_identity_digest=state.route_identity_digest,
        route_generation=state.route_generation,
        bundle_generation=max(1, state.owner_generation),
        privacy_root_generation=state.privacy_root_generation,
        ledger_roots_digest=object_digest,
        importer_roots_digest=_ZERO_DIGEST,
        privacy_roots_digest=state.privacy_root_digest,
        maintenance_pin_digest=_ZERO_DIGEST,
        captured_at=clock.now_utc(),
        live_object_ids=ordered_object_ids,
    )


def _initialize_fresh_bundle(path: Path, *, command: object, clock: ClockPort) -> None:
    db = _open_recovery_writer(path)
    try:
        initialize_bundle(
            db,
            {
                "owner_generation": "0",
                "owner_nonce": _nonce(),
                "protocol_version": "0.1",
                "route_generation": str(getattr(command, "route_generation")),
                "route_identity_digest": cast(str, getattr(command, "route_identity_digest")),
                "storage_schema_version": "1",
                "task_id": cast(str, getattr(command, "task_id")),
                "updated_at": format_rfc3339_millis(clock.now_utc()),
            },
        )
    finally:
        _close_db(db)


def _admitted_writers_for_session(
    catalog_db: apsw.Connection, task_id: str, session_id: str
) -> frozenset[str]:
    """Load durable writer IDs attached to one active session from completed starts."""

    rows = catalog_db.execute(
        "SELECT DISTINCT writer_id FROM start_operations "
        "WHERE session_id = ? AND state = 'complete'",
        (session_id,),
    ).fetchall()
    from yoetz.application.observation_materialize import observation_writer_id

    writers = frozenset(
        {*(cast(str, row[0]) for row in rows), observation_writer_id(task_id, session_id)}
    )
    if any(type(item) is not str for item in writers):
        raise ValueError("admitted_writer_ids_invalid")
    return writers


def _admitted_writers_for_session_from_path(
    catalog_path: Path, task_id: str, session_id: str
) -> frozenset[str]:
    """Read session writer admission through a short-lived private inspection connection."""

    catalog_db = open_read_only(catalog_path)
    try:
        return _admitted_writers_for_session(catalog_db, task_id, session_id)
    finally:
        _close_db(catalog_db)


def _inspect_common(
    *,
    catalog_path: Path,
    bundle_base: Path,
    route: object,
    admitted_writer_ids: frozenset[str],
    fresh_allocation: bool,
) -> _BundleInspection:
    task_id = cast(str, getattr(route, "task_id"))
    bundle_root = _safe_bundle_root(
        bundle_base, cast(str, getattr(route, "bundle_relpath")), task_id
    )
    state = recovery_module.inspect_recovery_state(
        bundle_root,
        catalog_path=catalog_path,
        task_id=task_id,
        route_generation=cast(int, getattr(route, "route_generation")),
        route_identity_digest=cast(str, getattr(route, "route_identity_digest")),
    )
    verdict = recovery_module.validate_recovery_tail(state)
    if type(admitted_writer_ids) is not frozenset or any(
        type(item) is not str for item in admitted_writer_ids
    ):
        raise ValueError("admitted_writer_ids_invalid")
    return _BundleInspection(
        route,
        bundle_root,
        bundle_root / _LEDGER_NAME,
        catalog_path,
        admitted_writer_ids,
        fresh_allocation,
        state,
        verdict,
    )


def build_runtime_adapter_factories(
    *,
    paths: _Paths,
    service_instance_id: str,
    service_generation: int,
    clock: ClockPort,
    ids: IdPort,
    secret_memory: object,
    catalog_db: apsw.Connection | None = None,
) -> RuntimeAdapterFactories:
    """Build durable local runtime adapter callbacks for one ready generation."""

    _install_sqlite_support_policy()
    catalog_path = _catalog_path(paths)
    _install_recovery_persistence(_RecoveryPersistence(catalog_path, clock))
    opened_dbs: dict[int, apsw.Connection] = {}
    object_root_dbs: dict[int, apsw.Connection] = {}
    importer_writers: dict[int, SqliteWriterThread] = {}

    async def inspect_route(route: object, access: RouteAccess) -> object:
        del access
        session_id = cast(str, getattr(route, "session_id"))

        def inspect() -> object:
            # Catalog and recovery inspection are synchronous APSW/file operations. Keep the
            # entire route snapshot off the control event loop; runtime.route() already exposes
            # this seam as async, so callers retain their normal deadline/cancellation contract.
            return _inspect_common(
                catalog_path=catalog_path,
                bundle_base=paths.bundle,
                route=route,
                admitted_writer_ids=_admitted_writers_for_session_from_path(
                    catalog_path, cast(str, getattr(route, "task_id")), session_id
                ),
                fresh_allocation=False,
            )

        return await asyncio.to_thread(inspect)

    async def inspect_provision(command: object) -> object:
        def inspect() -> object:
            route = TaskRoute(
                task_id=cast(str, getattr(command, "task_id")),
                session_id=cast(str, getattr(command, "session_id")),
                bundle_relpath=cast(str, getattr(command, "bundle_relpath")),
                route_generation=cast(int, getattr(command, "route_generation")),
                route_identity_digest=cast(str, getattr(command, "route_identity_digest")),
                state=TaskRouteState.ACTIVE,
                repository_privacy_commitment=cast(
                    str | None, getattr(command, "repository_privacy_commitment", None)
                ),
                parent_task_id=cast(str | None, getattr(command, "parent_task_id", None)),
                depth=cast(int, getattr(command, "depth", 0)),
                lineage_digest=cast(str | None, getattr(command, "lineage_digest", None)),
                origin=cast(LineageOrigin | None, getattr(command, "origin", None)),
                acceptance=cast(LineageAcceptance | None, getattr(command, "acceptance", None)),
                work_state=cast(WorkState, getattr(command, "work_state", WorkState.OPEN)),
            )
            bundle_root = _safe_bundle_root(
                paths.bundle,
                cast(str, getattr(command, "bundle_relpath")),
                cast(str, getattr(command, "task_id")),
            )
            ledger_path = bundle_root / _LEDGER_NAME
            fresh = not ledger_path.exists()
            if fresh:
                bundle_root.mkdir(mode=0o700, parents=True, exist_ok=False)
                bundle_root.chmod(0o700)
                _initialize_fresh_bundle(ledger_path, command=command, clock=clock)
            writer_id = cast(str, getattr(command, "writer_id"))
            return _inspect_common(
                catalog_path=catalog_path,
                bundle_base=paths.bundle,
                route=route,
                admitted_writer_ids=frozenset({writer_id}),
                fresh_allocation=fresh,
            )

        return await _run_blocking_joined(inspect, operation="runtime_inspect_provision_failed")

    async def acquire_fence(inspection: object, write: bool) -> OwnershipFence:
        if type(inspection) is not _BundleInspection:
            raise ValueError("runtime_inspection_invalid")
        if not write:
            state = cast(recovery_module.RecoveryState, inspection.recovery_state)
            fence = OwnershipFence(
                service_instance_id=service_instance_id,
                service_generation=service_generation,
                owner_generation=max(1, state.owner_generation),
                nonce=state.owner_nonce,
            )
            registrar = cast(
                Callable[[Path, OwnershipFence], None],
                getattr(connection_module, "_register_active_fence"),
            )
            await asyncio.to_thread(registrar, inspection.ledger_path, fence)
            return fence
        try:
            return await asyncio.to_thread(
                recovery_module.acquire_bundle_ownership,
                cast(recovery_module.RecoveryState, inspection.recovery_state),
                cast(recovery_module.RecoveryTailVerdict, inspection.recovery_verdict),
                service_instance_id=service_instance_id,
                service_generation=service_generation,
                owner_nonce=_nonce(),
                now=clock.now_utc(),
            )
        except ValueError as exc:
            if str(exc) != "recovery_ownership_conflict":
                raise
            raise PublicOperationError(
                PublicErrorCode.BUNDLE_BUSY,
                "Task ownership is contended; retry the same request.",
                True,
                safe_details={"reason_code": "ownership_contended"},
            ) from exc

    async def validate_fence(inspection: object, fence: OwnershipFence) -> None:
        if type(inspection) is not _BundleInspection:
            raise ValueError("runtime_inspection_invalid")
        backend = cast(
            _RecoveryPersistence,
            recovery_module._backend(),  # pyright: ignore[reportPrivateUsage]
        )
        await asyncio.to_thread(backend.verify_fence, inspection.recovery_state, fence)

    async def open_objects(
        inspection: object,
        keys: BundleKeys | None,
        fence: OwnershipFence,
        access: RouteAccess,
    ) -> ObjectStorePort:
        del fence, access
        if type(inspection) is not _BundleInspection or keys is None:
            raise ValueError("runtime_object_store_invalid")
        # ``LocalBundleRuntime._open_entry`` shields this opening task and waits for it during
        # generation teardown, so the returned connection remains owned even if the requesting
        # control call is cancelled while the worker performs schema verification.
        db = await asyncio.to_thread(open_read_only, inspection.ledger_path)
        try:
            store = EncryptedFilesObjectStore(
                bundle_root=inspection.bundle_root,
                bundle_keys=keys,
                secret_memory=secret_memory,  # pyright: ignore[reportArgumentType]
                id_port=ids,
                current_root_snapshot=lambda: _root_snapshot(inspection, db, clock, catalog_db),
            )
            object_root_dbs[id(store)] = db
            return store
        except BaseException:
            _close_db(db)
            raise

    async def open_ledger(
        inspection: object,
        objects: ObjectStorePort,
        fence: OwnershipFence,
        access: RouteAccess,
    ) -> LedgerPort:
        del access
        if type(inspection) is not _BundleInspection:
            raise ValueError("runtime_ledger_invalid")
        # The opening task is shielded by LocalBundleRuntime and joined by close(); this keeps the
        # writer and its fence lifetime paired when the caller's deadline expires.
        db = await asyncio.to_thread(open_writer, inspection.ledger_path)
        try:
            ledger = SqliteLedger(
                db=db,
                task_id=cast(str, getattr(inspection.route, "task_id")),
                ownership_fence=fence,
                clock=clock,
                ids=ids,
                objects=objects,
            )
            opened_dbs[id(ledger)] = db
            return ledger
        except BaseException:
            _close_db(db)
            raise

    async def open_importer(
        inspection: object,
        objects: ObjectStorePort,
        ledger: LedgerPort,
        fence: OwnershipFence,
        access: RouteAccess,
    ) -> ImporterPort:
        del access
        if type(inspection) is not _BundleInspection:
            raise ValueError("runtime_importer_invalid")
        route = inspection.route
        plans = CodexImportPlans(
            task_id=cast(str, getattr(route, "task_id")),
            objects=objects,
            clock=clock,
            ids=ids,
        )
        # SqliteWriterThread is likewise created inside the shielded opening task; teardown waits
        # for that task before closing the returned entry.
        writer = await asyncio.to_thread(SqliteWriterThread, inspection.ledger_path)
        try:
            importer = SqliteImporter(
                task_id=cast(str, getattr(route, "task_id")),
                admitted_session_id=cast(str, getattr(route, "session_id")),
                ownership_fence=fence,
                writer=writer,
                read_factory=lambda: open_read_only(inspection.ledger_path),
                objects=objects,
                ledger=ledger,
                clock=clock,
                ids=ids,
                plan_preparer=plans.prepare,
                plan_reader=plans.read,
            )
            importer_writers[id(importer)] = writer
            return importer
        except BaseException:
            writer.close()
            raise

    async def verify_start(
        inspection: object,
        runtime: TaskRuntime,
        expectation: StartMilestoneExpectation,
    ) -> StartCompletionEvidence:
        if type(inspection) is not _BundleInspection:
            raise ValueError("runtime_inspection_invalid")
        frontier: Frontier | None = None
        if expectation.milestone is not StartMilestone.BUNDLE_READY:
            frontier = await runtime.ledger.load_frontier()
        # StartCompletionEvidence.owner_generation is the start-lease / catalog generation
        # (service generation), not the per-bundle monotonic fence owner_generation.
        owner_generation = runtime.fence.service_generation
        frontier_value: CanonicalJsonValue = (
            None if frontier is None else cast(CanonicalJsonValue, dict(frontier.as_wire()))
        )
        value: dict[str, CanonicalJsonValue] = {
            "lifecycle_event_id": expectation.lifecycle_event_id,
            "lifecycle_frontier": frontier_value,
            "milestone": expectation.milestone.value,
            "owner_generation": owner_generation,
            "response_envelope_digest": expectation.response_envelope_digest,
            "response_object_id": expectation.response_object_id,
            "result_digest": expectation.result_digest,
            "route_generation": expectation.route_generation,
            "route_identity_digest": expectation.route_identity_digest,
            "session_id": expectation.session_id,
            "task_id": expectation.task_id,
            "writer_id": expectation.writer_id,
        }
        return StartCompletionEvidence(
            expectation.milestone,
            expectation.task_id,
            expectation.session_id,
            expectation.writer_id,
            expectation.lifecycle_event_id,
            expectation.route_generation,
            expectation.route_identity_digest,
            owner_generation,
            frontier,
            expectation.response_object_id,
            expectation.response_envelope_digest,
            expectation.result_digest,
            canonical_digest(value),
        )

    async def close_entry(
        inspection: object,
        objects: ObjectStorePort | None,
        ledger: LedgerPort | None,
        importer: object | None,
        fence: OwnershipFence | None,
    ) -> None:
        if importer is not None:
            writer = importer_writers.pop(id(importer), None)
            if writer is not None:
                writer.close()
        if objects is not None:
            _close_db(object_root_dbs.pop(id(objects), None))
        if ledger is not None:
            _close_db(opened_dbs.pop(id(ledger), None))
        if fence is not None:
            if type(inspection) is not _BundleInspection:
                return
            clearer = cast(
                Callable[[Path, OwnershipFence | None], None],
                getattr(connection_module, "_clear_active_fence"),
            )
            clearer(inspection.ledger_path, fence)

    return RuntimeAdapterFactories(
        current_service_generation=lambda: service_generation,
        inspect_route=inspect_route,
        inspect_provision=inspect_provision,
        acquire_fence=acquire_fence,
        validate_fence=validate_fence,
        open_objects=open_objects,
        open_ledger=open_ledger,
        open_importer=open_importer,
        verify_start=verify_start,
        close_entry=close_entry,
    )


# The agent-context allowlist shipped before ADR-009 permitted verification output by default.
# Kept only to recognize an installation still carrying that untouched seed; see
# `_reseed_untouched_default_policy`.
_LEGACY_AGENT_CONTEXT_CATEGORIES: Final = (
    DataCategory.BOUNDED_STRUCTURAL_METADATA,
    DataCategory.DECLARED_FILE_TYPE,
)
_LEGACY_AGENT_CONTEXT_DATA_CLASSES: Final = (DataClass.PUBLIC_STRUCTURAL,)

# Bootstrap seed identity. The revision names the shipped default's contents, so widening the
# default mints a distinct `policy_digest` instead of two different payloads sharing one digest:
# that digest is the CAS precondition for later tightenings and is exposed as `effective_digest`.
# `None` reproduces the pre-ADR-009 payload and exists only to recognize an untouched old seed.
_BOOTSTRAP_SEED_SCHEMA: Final = "yoetz.privacy-policy.bootstrap/1"
# 2026-07-24: agent-context verification output. 2026-08-03: default-on structural update_checks.
_BOOTSTRAP_DEFAULT_REVISION: Final = "2026-08-03-package-update-checks"
_BOOTSTRAP_REVISION_VERIFICATION_OUTPUT: Final = "2026-07-24-verification-output"
_UPDATE_CHECKS_MAX_BYTES: Final = 4096
_UPDATE_CHECKS_MAX_TOKENS: Final = 1024
_UPDATE_CHECKS_TTL_SECONDS: Final = 60


def _bootstrap_seed_digest(installation_id: str, *, revision: str | None) -> str:
    payload: dict[str, CanonicalJsonValue] = {
        "installation_id": installation_id,
        "profile": "local_only",
        "schema": _BOOTSTRAP_SEED_SCHEMA,
    }
    if revision is not None:
        payload["default_revision"] = revision
    return canonical_digest(payload)


def _semantic_prepared_byte_ceiling(policy: PrivacyPolicy) -> int | None:
    """The effective AI-powered review channel ceiling, in prepared-payload bytes (issue #907).

    The gateway blocks a prepared review packet over the channel's ``max_bytes`` or over its
    ``max_tokens`` estimated at four bytes per token; the case builder plans below the narrower
    of the two so a narrower owner ceiling drops the lowest-ranked excerpts instead of the whole
    review. ``None`` (zero means unset) leaves the schema maximum.
    """

    llm = next(
        (item for item in policy.channel_policies if item.channel is EgressChannel.LLM_INFERENCE),
        None,
    )
    if llm is None:
        return None
    limits = [
        limit
        for limit in (llm.max_bytes, llm.max_tokens * EGRESS_BYTES_PER_TOKEN_ESTIMATE)
        if limit > 0
    ]
    return min(limits) if limits else None


def _disabled_channel_row(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel=channel,
        enabled=False,
        allowed_categories=(),
        allowed_data_classes=(),
        provider_binding=None,
        allowed_purposes=(),
        scope_ceiling=AuthorizationScopeKind.MACHINE,
        preview_required=False,
        max_bytes=0,
        max_tokens=0,
        authorization_ttl_seconds=0,
    )


def _update_checks_channel_row() -> ChannelPolicy:
    return ChannelPolicy(
        channel=EgressChannel.UPDATE_CHECKS,
        enabled=True,
        allowed_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        allowed_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
        provider_binding=None,
        allowed_purposes=("package-update-check",),
        scope_ceiling=AuthorizationScopeKind.MACHINE,
        preview_required=False,
        max_bytes=_UPDATE_CHECKS_MAX_BYTES,
        max_tokens=_UPDATE_CHECKS_MAX_TOKENS,
        authorization_ttl_seconds=_UPDATE_CHECKS_TTL_SECONDS,
    )


def _shipped_default_policy(policy: PrivacyPolicy, *, revision: str | None) -> PrivacyPolicy:
    """Rebuild a shipped default policy at one revision under an existing policy's identity."""

    rebuilt = _product_default_policy(
        installation_id=policy.effective_scope.installation_id,
        policy_id=policy.policy_id,
        policy_digest=_bootstrap_seed_digest(
            policy.effective_scope.installation_id, revision=revision
        ),
        created_at=policy.created_at,
        revision=revision,
    )
    if revision is not None:
        return rebuilt
    return replace(
        rebuilt,
        agent_context_categories=_LEGACY_AGENT_CONTEXT_CATEGORIES,
        agent_context_data_classes=_LEGACY_AGENT_CONTEXT_DATA_CLASSES,
    )


async def _reseed_untouched_default_policy(
    policies: CatalogPrivacyPolicyStore,
    scope: AuthorizationScope,
    policy: PrivacyPolicy,
) -> PrivacyPolicy:
    """Carry an untouched older bootstrap default forward to the current shipped default.

    Without this, an installation seeded before the default widened keeps the prior allowlist
    forever. Recognition is exact in every field, including the bootstrap seed digest, and the
    store additionally requires first-run seed provenance, so an owner policy that reproduces an
    old default's contents is left alone.
    """

    for previous in (None, _BOOTSTRAP_REVISION_VERIFICATION_OUTPUT):
        previous_default = replace(
            _shipped_default_policy(policy, revision=previous), version=policy.version
        )
        if policy == previous_default:
            replacement = replace(
                _shipped_default_policy(policy, revision=_BOOTSTRAP_DEFAULT_REVISION),
                version=policy.version + 1,
            )
            return await policies.reseed_untouched_bootstrap_default(
                scope, expected_current=policy, replacement=replacement
            )
    return policy


def _product_default_policy(
    *,
    installation_id: str,
    policy_id: str,
    policy_digest: str,
    created_at: datetime,
    revision: str | None,
) -> PrivacyPolicy:
    """Shipped first-run machine policy for one bootstrap revision.

    Config.toml bootstrap remains all-denied (fail-safe file seed). The durable catalog seed is
    the product default: ``local_only``, LLM off, structural ``update_checks`` on (opt-out), other
    non-LLM channels off, ``network_egress_permitted`` true only because update checks are on.
    Older revisions reconstruct all-denied network rows so reseed recognition stays exact.
    """

    safe = safe_privacy_bootstrap()
    # Config.toml generation-1 seed must remain fail-safe all-denied; it is not durable policy.
    if safe.network_egress_permitted or safe.local_model_enabled:
        raise ValueError("privacy_bootstrap_unsafe")
    if any(safe.channel_policies.model_dump().values()):
        raise ValueError("privacy_bootstrap_unsafe")

    enable_update_checks = revision == _BOOTSTRAP_DEFAULT_REVISION
    channels = tuple(
        (
            _update_checks_channel_row()
            if enable_update_checks and channel is EgressChannel.UPDATE_CHECKS
            else _disabled_channel_row(channel)
        )
        for channel in sorted(EgressChannel, key=lambda item: item.value)
    )
    return PrivacyPolicy(
        policy_id=policy_id,
        version=1,
        policy_digest=policy_digest,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=enable_update_checks,
        effective_scope=AuthorizationScope(AuthorizationScopeKind.MACHINE, installation_id),
        channel_policies=channels,
        local_model_enabled=False,
        local_model_binding=None,
        local_model_categories=(),
        local_model_data_classes=(),
        # Default LOCAL_ONLY: agent context may receive Yoetz-authored verification
        # projection content (findings, obligations, receipt sections/human_text) for the
        # requesting agent's own task. Observation-derived and vault material stay blocked.
        # See ADR-009 default agent-context disclosure of verification output.
        agent_context_categories=(
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.DECLARED_FILE_TYPE,
            DataCategory.FINDING_SUMMARY,
            DataCategory.OBLIGATION_TEXT,
        ),
        agent_context_data_classes=(
            DataClass.PUBLIC_STRUCTURAL,
            DataClass.ORDINARY_USER_CONTENT,
        ),
        trusted_human_control_categories=tuple(DataCategory),
        trusted_human_control_data_classes=(
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
            DataClass.SENSITIVE_CONFIDENTIAL,
        ),
        created_at=created_at,
    )


def _denied_policy(
    *,
    installation_id: str,
    policy_id: str,
    policy_digest: str,
    created_at: datetime,
) -> PrivacyPolicy:
    """Current product default seed (alias kept for call sites and tests)."""

    return _product_default_policy(
        installation_id=installation_id,
        policy_id=policy_id,
        policy_digest=policy_digest,
        created_at=created_at,
        revision=_BOOTSTRAP_DEFAULT_REVISION,
    )


def build_local_privacy_enforcer() -> LocalPrivacyEnforcer:
    """Compose the production local classifier with its trusted provenance resolver.

    Without a resolver every agent-context item is ambiguous, so the INTERFACES
    ``DisclosureProvenance`` rule never fires and an agent cannot read back even the evidence it
    published (issue #914). The resolver only consults ledger authorship the service read at the
    page's frozen frontier; the never-send scan, absolute data classes and the per-projection
    receipt are unchanged.
    """

    return LocalPrivacyEnforcer(provenance_resolver=LedgerAuthorshipProvenanceResolver())


async def build_privacy_coordinator(
    *,
    catalog_db: apsw.Connection,
    installation_id: str,
    service_generation: int,
    vault_generation: int,
    vault: _Vault,
    clock: ClockPort,
    ids: IdPort,
    config: YoetzConfig | None = None,
) -> tuple[object, PrivacyPolicy, object]:
    """Build and reconcile the fail-closed local privacy coordinator."""

    policies = CatalogPrivacyPolicyStore(catalog_db, clock)
    classifier = build_local_privacy_enforcer()
    audit_key = vault.installation_mac_handle(MacKeyPurpose.PRIVACY_AUDIT)
    audit = CatalogPrivacyAudit(
        catalog_db,
        cast(ObjectStorePort, _PrivacyContentObjectStore(ids)),
        audit_key,  # pyright: ignore[reportArgumentType]
        clock,
        service_generation=service_generation,
    )
    builders = external_factory_builders_from_config(
        None if config is None else config.provider,
        None if config is None else config.external_runtime,
        clock=clock,
        paired=config is not None and config.semantic_fallback is not None,
    )

    async def repository_authority_is_current(
        scope: AuthorizationScope, expected_authority_digest: str
    ) -> bool:
        try:
            snapshot = await policies.repository_authority(scope)
        except Exception:
            return False
        return (
            snapshot.grant_state == "granted"
            and snapshot.repository_privacy_commitment == scope.workspace_ref_commitment
            and snapshot.authority_digest == expected_authority_digest
        )

    gateway = PolicyEnforcingOutboundGateway(
        external_factory_builders=builders,  # type: ignore[arg-type]
        local_model_registry=InstalledLocalModelProfileRegistry(),
        local_model_resolver=None,
        credential_minter=_CredentialMinter(vault),
        audit=audit,
        classifier=classifier,
        audit_mac=audit_key,  # pyright: ignore[reportArgumentType]
        clock=clock,
        ids=ids,
        repository_authority_validator=repository_authority_is_current,
    )
    machine_scope = AuthorizationScope(AuthorizationScopeKind.MACHINE, installation_id)
    # Bootstrap seed is first-run only. Later unlocks must reuse the durable machine policy;
    # minting a fresh policy_id/created_at each ready build would conflict with seed_if_absent's
    # identity-equal check and fail unlock after the first successful ready activation.
    try:
        effective = await policies.effective_policy(machine_scope)
        policy = await _reseed_untouched_default_policy(policies, machine_scope, effective.policy)
        if policy is not effective.policy:
            effective = await policies.effective_policy(machine_scope)
    except ValueError as exc:
        if exc.args != ("privacy_policy_missing",):
            raise
        seed_digest = _bootstrap_seed_digest(installation_id, revision=_BOOTSTRAP_DEFAULT_REVISION)
        try:
            policy = await seed_policy_if_absent(
                _denied_policy(
                    installation_id=installation_id,
                    policy_id=ids.new(IdKind.PRIVACY_POLICY),
                    policy_digest=seed_digest,
                    created_at=clock.now_utc(),
                ),
                policies,
            )
        except ValueError as seed_exc:
            # Concurrent first-run race: another ready build committed a different identity.
            # Never overwrite; load the durable winner.
            if seed_exc.args != ("privacy_policy_seed_conflict",):
                raise
            effective = await policies.effective_policy(machine_scope)
            policy = effective.policy
        else:
            effective = await policies.effective_policy(machine_scope)
    authority = HumanAuthorityCapability(
        "established_passphrase",
        canonical_digest(
            {
                "service_generation": str(service_generation),
                "source": "established_passphrase",
                "vault_generation": str(vault_generation),
                "vault_mode": str(getattr(vault.mode, "value", vault.mode)),
            }
        ),
        service_generation,
        str(getattr(vault.mode, "value", vault.mode)),
        vault_generation,
        True,
    )
    coordinator = PrivacyCoordinator(
        policies,
        classifier,
        audit,
        gateway,
        clock,
        ids,
        service_generation=service_generation,
        human_authority=authority,
        data_use_resolver=gateway.bound_data_use_profile,
    )
    policy_app = PrivacyPolicyApplication(
        policies,
        audit,
        gateway,
        clock,
        ids,
        machine_scope,
    )
    coordinator.bind_policy_application(policy_app)
    return (
        coordinator,
        policy,
        gateway,
    )


def _version_json() -> Mapping[str, CanonicalJsonValue]:
    value = strict_json_parse(
        version_manifest_json(build_version_manifest(), include_resources=False)
    )
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise ValueError("version_manifest_invalid")
    return cast(Mapping[str, CanonicalJsonValue], value)


def _receipt_versions(manifest: Mapping[str, CanonicalJsonValue]) -> ReceiptVersionSlice:
    policies = manifest["policy_versions"]
    schemas = manifest["request_result_schema_versions"]
    if type(policies) is not list or not isinstance(schemas, Mapping):
        raise ValueError("version_manifest_invalid")
    policy_versions: list[PolicyVersionEntry] = []
    for item in policies:
        if type(item) is not str:
            raise ValueError("version_manifest_invalid")
        parts = item.split("/", 1)
        if len(parts) != 2:
            raise ValueError("version_manifest_invalid")
        policy_versions.append(PolicyVersionEntry(parts[0], parts[1]))
    schema_versions: list[SchemaVersionEntry] = []
    for schema_id, schema_version in schemas.items():
        if type(schema_id) is not str or type(schema_version) is not str:
            raise ValueError("version_manifest_invalid")
        schema_versions.append(SchemaVersionEntry(schema_id, schema_version))
    return ReceiptVersionSlice(
        package_name="yoetz",
        package_version=cast(str, manifest["package_version"]),
        protocol_version=cast(str, manifest["protocol_version"]),
        engine_version=cast(str, manifest["engine_version"]),
        projection_version=cast(str, manifest["projection_version"]),
        object_format_version=cast(str, manifest["object_format_version"]),
        catalog_schema_version=cast(str, manifest["catalog_schema_version"]),
        bundle_schema_version=cast(str, manifest["bundle_schema_version"]),
        policy_versions=tuple(sorted(policy_versions, key=lambda item: item.policy_id.encode())),
        schema_versions=tuple(sorted(schema_versions, key=lambda item: item.schema_id.encode())),
        resource_manifest_digest=cast(str, manifest["resource_manifest_digest"]),
    )


async def _semantic_not_configured(
    frozen: FrozenCase,
    findings: tuple[object, ...],
    runtime: TaskRuntime | None = None,
    lineage_evaluation: LineageEvaluation | None = None,
    require_complete_specification: bool = False,
    final_review: bool = False,
) -> FinalSemanticEvaluation:
    """Explicit path when AI-powered review is enabled but no provider endpoint is bound."""

    del frozen, findings, runtime, lineage_evaluation, require_complete_specification
    del final_review
    return FinalSemanticEvaluation(
        SemanticStatus.NOT_CONFIGURED, SemanticReason.PROVIDER_NOT_CONFIGURED
    )


async def _semantic_provider_unbound(
    frozen: FrozenCase,
    findings: tuple[object, ...],
    runtime: TaskRuntime | None = None,
    lineage_evaluation: LineageEvaluation | None = None,
    require_complete_specification: bool = False,
    final_review: bool = False,
) -> FinalSemanticEvaluation:
    """AI-powered review is enabled, but no external provider endpoint is configured."""

    record_bounded_event_without_raising(
        component="semantic_composition",
        operation="semantic_not_dispatched_provider_unbound",
        reason=SemanticReason.PROVIDER_NOT_CONFIGURED.value,
        request_id=frozen.lease.operation_id,
    )
    return await _semantic_not_configured(
        frozen,
        findings,
        runtime,
        lineage_evaluation,
        require_complete_specification,
    )


def _map_blocked(outcome: PrivacyOutcome, reason: object) -> FinalSemanticEvaluation:
    """Map pre-dispatch privacy blocks to exact AI-powered review status/reason pairs."""

    if outcome is PrivacyOutcome.CHANNEL_UNAVAILABLE:
        # Distinct from missing credential/endpoint: the channel is present but policy forbids it.
        return FinalSemanticEvaluation(
            SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.CHANNEL_DISABLED
        )
    if outcome is PrivacyOutcome.BLOCKED_FORBIDDEN_DATA:
        return FinalSemanticEvaluation(
            SemanticStatus.BLOCKED_FORBIDDEN_DATA, SemanticReason.NEVER_SEND_DETECTED
        )
    if outcome is PrivacyOutcome.CLASSIFICATION_UNCERTAIN:
        return FinalSemanticEvaluation(
            SemanticStatus.CLASSIFICATION_UNCERTAIN, SemanticReason.CLASSIFICATION_UNCERTAIN
        )
    if outcome is PrivacyOutcome.HUMAN_DENIED:
        return FinalSemanticEvaluation(SemanticStatus.HUMAN_DENIED, SemanticReason.HUMAN_DENIED)
    if outcome is PrivacyOutcome.APPROVAL_EXPIRED:
        return FinalSemanticEvaluation(
            SemanticStatus.APPROVAL_EXPIRED, SemanticReason.HUMAN_APPROVAL_EXPIRED
        )
    if outcome is PrivacyOutcome.TIMEOUT:
        return FinalSemanticEvaluation(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)
    if outcome is PrivacyOutcome.AUDIT_FAILED:
        return FinalSemanticEvaluation(
            SemanticStatus.UNAVAILABLE, SemanticReason.AUDIT_RESERVATION_UNAVAILABLE
        )
    if outcome is PrivacyOutcome.TRANSPORT_FAILED:
        return FinalSemanticEvaluation(
            SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE
        )
    if outcome is PrivacyOutcome.BLOCKED_BY_POLICY:
        reason_name = getattr(reason, "name", None)
        if reason_name == "PURPOSE_NOT_ALLOWED":
            return FinalSemanticEvaluation(
                SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.CHANNEL_DISABLED
            )
        if reason_name == "DESTINATION_NOT_ALLOWED":
            return FinalSemanticEvaluation(
                SemanticStatus.BLOCKED_BY_POLICY,
                SemanticReason.PROVIDER_BINDING_NOT_AUTHORIZED,
            )
        if reason_name == "SCOPE_MISMATCH":
            return FinalSemanticEvaluation(
                SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.SCOPE_NOT_AUTHORIZED
            )
        if reason_name == "CATEGORY_NOT_ALLOWED":
            return FinalSemanticEvaluation(
                SemanticStatus.BLOCKED_BY_POLICY,
                SemanticReason.CONTENT_CATEGORY_NOT_AUTHORIZED,
            )
        return FinalSemanticEvaluation(
            SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.NETWORK_EGRESS_DENIED
        )
    return FinalSemanticEvaluation(SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE)


def _provider_provenance(
    result: SemanticEgressSuccess | SemanticEgressProviderOutcome,
    *,
    status: SemanticStatus,
    reason: SemanticReason,
    attempt_id: str,
) -> SemanticProvenance | None:
    """Bind a completed attempt to its dispatch-specific durable privacy authority."""

    if result.privacy_receipt_id is None:
        return None
    if result.dispatch_kind in {
        SemanticDispatchKind.EXTERNAL,
        SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH,
    }:
        if result.authorization_id is None or result.request_commitment is None:
            return None
        egress_authorization_id = result.authorization_id
        local_disclosure_reservation_id = None
        request_commitment = result.request_commitment
    elif result.dispatch_kind is SemanticDispatchKind.LOCAL_MODEL:
        if result.authorization_id is not None or result.request_commitment is not None:
            return None
        egress_authorization_id = None
        local_disclosure_reservation_id = result.privacy_proposal_id
        request_commitment = None
    else:
        return None
    attempt = result.result.provenance
    return SemanticProvenance(
        provider=attempt.provider,
        endpoint_profile_id=attempt.endpoint_profile_id,
        endpoint_profile_version=attempt.endpoint_profile_version,
        model=attempt.model,
        sdk_version=attempt.sdk_version,
        prompt_digest=attempt.prompt_digest,
        schema_digest=attempt.schema_digest,
        policy_digest=attempt.policy_digest,
        privacy_policy_digest=attempt.privacy_policy_digest,
        sampling_params=attempt.sampling_params,
        latency_ms=attempt.latency_ms,
        semantic_attempt_id=attempt_id,
        dispatch_kind=result.dispatch_kind,
        privacy_receipt_id=result.privacy_receipt_id,
        status=status,
        reason=reason,
        provider_request_id=attempt.provider_request_id,
        token_usage=attempt.token_usage,
        cost_fields=attempt.cost_fields,
        failure_class=attempt.failure_class,
        egress_authorization_id=egress_authorization_id,
        local_disclosure_reservation_id=local_disclosure_reservation_id,
        request_commitment=request_commitment,
        runtime_evidence=attempt.runtime_evidence,
    )


def _egress_withheld_item_ids(result: object) -> tuple[str, ...]:
    """Read the bounded heuristic omission identities from an egress result.

    Privacy owns the result dataclasses and keeps this field optional for old in-process fakes
    and recovery rows.  The final evaluation validates the tuple's canonical bounded shape before
    it can reach a check result or a durable response object.
    """

    value = getattr(result, "withheld_item_ids", ())
    return cast(tuple[str, ...], value) if type(value) is tuple else ()


def _egress_redacted_values(result: object) -> tuple[SemanticRedactedValue, ...]:
    """Read the bounded PL2-1 item refs and line numbers from an egress result.

    Optional for old in-process fakes; ``FinalSemanticEvaluation`` re-validates the shape.
    """

    value = getattr(result, "redacted_values", ())
    return cast(tuple[SemanticRedactedValue, ...], value) if type(value) is tuple else ()


def _egress_case_content_gaps(result: object) -> tuple[str, ...]:
    """Project bounded egress transformations into the existing check coverage vocabulary."""

    # Egress redaction replaced credential-like values in the packet sent to the external model.
    # It bounds that review only, never local proof (issue #982), so it has its own review-scoped
    # code instead of the capture-time ``content_redacted``.
    # An item withheld outright is also a case-content gap, so the check stamps it on every
    # AI-powered finding the review raises and it can serve as that finding's capture baseline.
    gaps: list[str] = []
    value = getattr(result, "redacted_span_count", 0)
    if type(value) is int and value > 0:
        gaps.append(SEMANTIC_REVIEW_VALUE_REDACTED_GAP)
    if _egress_withheld_item_ids(result):
        gaps.append(SEMANTIC_REVIEW_ITEM_WITHHELD_GAP)
    return tuple(sorted(gaps, key=str.encode))


def _provider_manifest_has_redaction(manifest: object) -> bool:
    """Recover the redaction coverage bit from the exact provider-bound manifest."""

    if not isinstance(manifest, Mapping):
        return False
    typed_manifest = cast(Mapping[str, object], manifest)
    for name in (
        "specification",
        "current_diff",
        "caller_evidence",
        "latest_verification",
        "prior_finding_context",
    ):
        section = typed_manifest.get(name)
        if not isinstance(section, Mapping):
            continue
        reasons = cast(Mapping[str, object], section).get("omission_reasons")
        if isinstance(reasons, list) and "redacted_never_send" in reasons:
            return True
    return False


def _map_provider_outcome(
    result: SemanticEgressProviderOutcome, *, attempt_id: str
) -> FinalSemanticEvaluation:  # attempt_id is the durable semantic_attempts row identity
    provider = result.result
    withheld_item_ids = _egress_withheld_item_ids(result)
    status: SemanticStatus
    reason: SemanticReason
    if type(provider) is SemanticResultRefused:
        status, reason = SemanticStatus.REFUSED, SemanticReason.PROVIDER_REFUSED
    elif type(provider) is SemanticResultTimeout:
        status, reason = SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT
    elif type(provider) is SemanticResultInvalid:
        status = SemanticStatus.INVALID
        failure_class = provider.provenance.failure_class
        if failure_class is SemanticFailureClass.RESPONSE_CONTENT:
            reason = SemanticReason.RESPONSE_CONTENT_INVALID
        else:
            # Constrained-schema mismatch / non-JSON / empty output: structural schema stage.
            reason = SemanticReason.RESPONSE_SCHEMA_INVALID
        runtime = provider.provenance.runtime_evidence
        if runtime is not None:
            # The public reason is a closed pair; the exact stage at which an external runtime's
            # answer failed local validation is the owner-only diagnostic that makes the failure
            # actionable. `failure_stage` is a closed registry token, never provider text.
            record_bounded_event_without_raising(
                component="semantic_composition",
                operation="semantic_provider_attempt_invalid",
                reason="unclassified" if runtime.failure_stage is None else runtime.failure_stage,
            )
    elif type(provider) is SemanticResultLate:
        status, reason = SemanticStatus.LATE, SemanticReason.DEADLINE_AUTHORITY_LOST
    elif type(provider) is SemanticResultUnavailable:
        status = SemanticStatus.UNAVAILABLE
        failure_class = provider.provenance.failure_class
        runtime = provider.provenance.runtime_evidence
        if (
            runtime is not None
            and runtime.turn_acknowledged
            and failure_class is SemanticFailureClass.TRANSPORT
        ):
            reason = SemanticReason.OUTCOME_UNKNOWN
        elif failure_class is SemanticFailureClass.RATE_LIMITED:
            reason = SemanticReason.PROVIDER_RATE_LIMITED
        elif failure_class is SemanticFailureClass.QUOTA_EXHAUSTED:
            reason = SemanticReason.PROVIDER_QUOTA_EXHAUSTED
        elif failure_class is SemanticFailureClass.RESPONSE_CONTENT:
            # The privacy gateway uses the closed response-content class for a rendered-body
            # never-send refusal.  Preserve that typed pre-dispatch fact so required review gets
            # the privacy recovery directive instead of being misreported as transport loss.
            status = SemanticStatus.BLOCKED_FORBIDDEN_DATA
            reason = SemanticReason.NEVER_SEND_DETECTED
        else:
            # `transport_unavailable` is the public catch-all for every remaining class:
            # a rejected credential, a forbidden binding, a provider outage, an unsupported
            # profile, and a genuine socket failure all arrive here and read identically. The
            # public taxonomy stays closed, but the owner needs the distinction to act, so the
            # exact class is recorded as a durable owner-only diagnostic. `SemanticFailureClass`
            # is a closed enum, so this carries no provider-controlled text.
            record_bounded_event_without_raising(
                component="semantic_composition",
                operation="semantic_provider_attempt_unavailable",
                reason="unclassified" if failure_class is None else failure_class.value,
            )
            reason = SemanticReason.TRANSPORT_UNAVAILABLE
    else:
        return FinalSemanticEvaluation(
            SemanticStatus.FAILED,
            SemanticReason.COORDINATOR_FAILURE,
            semantic_withheld_item_ids=withheld_item_ids,
            semantic_redacted_values=_egress_redacted_values(result),
            case_content_gaps=_egress_case_content_gaps(result),
        )
    if status is SemanticStatus.BLOCKED_FORBIDDEN_DATA:
        # A rendered-body privacy refusal is pre-dispatch.  Its typed result intentionally has no
        # provider request commitment, so asking the normal provider-provenance gate to certify
        # it would downgrade the bounded refusal to ``receipt_persistence_unknown``.
        return FinalSemanticEvaluation(
            status,
            reason,
            semantic_withheld_item_ids=withheld_item_ids,
            semantic_redacted_values=_egress_redacted_values(result),
            case_content_gaps=_egress_case_content_gaps(result),
        )
    provenance = _provider_provenance(result, status=status, reason=reason, attempt_id=attempt_id)
    if provenance is None:
        return FinalSemanticEvaluation(
            SemanticStatus.UNAVAILABLE,
            SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
            semantic_withheld_item_ids=withheld_item_ids,
            semantic_redacted_values=_egress_redacted_values(result),
            case_content_gaps=_egress_case_content_gaps(result),
        )
    return FinalSemanticEvaluation(
        status,
        reason,
        provenance=provenance,
        semantic_withheld_item_ids=withheld_item_ids,
        semantic_redacted_values=_egress_redacted_values(result),
        case_content_gaps=_egress_case_content_gaps(result),
    )


def _map_egress_to_final(
    result: object,
    ids: IdPort | None = None,
    *,
    attempt_id: str | None = None,
    operation_request_id: str | None = None,
    projection: ProjectionState | None = None,
) -> FinalSemanticEvaluation:
    """Map privacy egress outcomes to check FinalSemanticEvaluation without inventing findings.

    Production passes the durable ``attempt_id`` and the frozen case's ``projection``, which lets a
    success name the result and evidence records its sent packet carried under their recording
    events (issue #904). Tests may pass only an ``IdPort`` to mint a provisional attempt identity
    for mapping assertions.
    """

    resolved_attempt = attempt_id
    if resolved_attempt is None:
        if ids is None:
            raise TypeError("semantic_attempt_id_required")
        resolved_attempt = ids.new(IdKind.SEMANTIC_ATTEMPT)

    if type(result) is SemanticEgressSuccess:
        withheld_item_ids = _egress_withheld_item_ids(result)
        provenance = _provider_provenance(
            result,
            status=SemanticStatus.SUCCEEDED,
            reason=SemanticReason.SEMANTIC_COMPLETED,
            attempt_id=resolved_attempt,
        )
        if provenance is None:
            return FinalSemanticEvaluation(
                SemanticStatus.UNAVAILABLE,
                SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
                semantic_withheld_item_ids=withheld_item_ids,
                semantic_redacted_values=_egress_redacted_values(result),
                case_content_gaps=_egress_case_content_gaps(result),
            )
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=result.result.judgment,
            provenance=provenance,
            case_included_refs=(
                None
                if result.disclosure is None
                else result.disclosure.carried
                if projection is None
                else sent_ledger_refs(result.disclosure, projection)
            ),
            case_withheld_refs=(
                None
                if result.disclosure is None
                else result.disclosure.withheld - result.disclosure.privacy_withheld
            ),
            case_privacy_withheld_refs=(
                frozenset() if result.disclosure is None else result.disclosure.privacy_withheld
            ),
            semantic_withheld_item_ids=withheld_item_ids,
            semantic_redacted_values=_egress_redacted_values(result),
            provider_input_manifest=(
                None if result.disclosure is None else result.disclosure.provider_input_manifest
            ),
            provider_input_text_by_ref=(
                None if result.disclosure is None else result.disclosure.provider_input_text_by_ref
            ),
            provider_input_manifest_failure=result.provider_input_manifest_failure,
            case_content_gaps=_egress_case_content_gaps(result),
        )
    if type(result) is SemanticEgressAwaitingHuman:
        # The proposal id and its expiry are the only things that make this branch recoverable.
        # Dropping them is what turned "a human must approve" into an unanswerable instruction.
        #
        # The continuation names the request the *caller* replays, which is the check operation —
        # not ``result.request_id``, which on the durable path is the per-attempt provider request
        # id. Telling a caller to replay a provider request id would name a request it never sent.
        return FinalSemanticEvaluation(
            SemanticStatus.AWAITING_HUMAN,
            SemanticReason.HUMAN_APPROVAL_REQUIRED,
            semantic_withheld_item_ids=_egress_withheld_item_ids(result),
            semantic_redacted_values=_egress_redacted_values(result),
            case_content_gaps=_egress_case_content_gaps(result),
            continuation=disclosure_continuation(
                pending_id=result.privacy_proposal_id,
                expires_at=result.expires_at,
                request_id=(
                    result.request_id if operation_request_id is None else operation_request_id
                ),
            ),
        )
    if type(result) is SemanticEgressAttemptUnknown:
        return FinalSemanticEvaluation(
            SemanticStatus.UNAVAILABLE,
            SemanticReason.OUTCOME_UNKNOWN,
            semantic_withheld_item_ids=_egress_withheld_item_ids(result),
            semantic_redacted_values=_egress_redacted_values(result),
            case_content_gaps=_egress_case_content_gaps(result),
        )
    if type(result) is SemanticEgressBlocked:
        return replace(
            _map_blocked(result.outcome, result.reason),
            semantic_withheld_item_ids=_egress_withheld_item_ids(result),
            semantic_redacted_values=_egress_redacted_values(result),
            case_content_gaps=_egress_case_content_gaps(result),
        )
    if type(result) is SemanticEgressProviderOutcome:
        return _map_provider_outcome(result, attempt_id=resolved_attempt)
    return FinalSemanticEvaluation(SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE)


def _progress_millis(value: datetime) -> datetime:
    return value.replace(microsecond=value.microsecond - value.microsecond % 1000)


async def _begin_semantic_progress(
    runtime: TaskRuntime, job: SemanticJobRecord, deadline_at: datetime, clock: ClockPort
) -> None:
    """Create the job's ``queued`` progress row; progress never blocks or fails a check."""

    begin = getattr(runtime.ledger, "begin_semantic_progress", None)
    if not callable(begin):
        return
    try:
        await cast(Callable[[str, datetime, datetime], Awaitable[None]], begin)(
            job.job_id,
            _progress_millis(clock.now_utc()),
            _progress_millis(deadline_at),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - telemetry must not fail the check
        record_unexpected_exception_without_raising(
            exc,
            component="semantic_progress",
            operation="semantic_progress_begin_failed",
            request_id=job.operation_id,
        )


def _attempt_progress_sink(
    runtime: TaskRuntime, handle: SemanticAttemptHandle, clock: ClockPort
) -> SemanticProgressSink | None:
    """Bind structural phase writes to exactly one claimed physical attempt."""

    advance = getattr(runtime.ledger, "advance_semantic_progress", None)
    if not callable(advance):
        return None
    write = cast(
        Callable[[SemanticAttemptHandle, SemanticProgressPhase, datetime], Awaitable[bool]],
        advance,
    )

    async def _sink(phase: SemanticProgressPhase) -> None:
        await write(handle, phase, _progress_millis(clock.now_utc()))

    return _sink


@dataclass(frozen=True, slots=True)
class _SemanticExecution:
    provider: ProviderBinding
    fallback_binding: ProviderBinding | None
    fallback_plan: SemanticFallbackPlan | None
    max_retries: int
    primary_expires_at: datetime
    expires_at: datetime
    fallback_timeout_seconds: float
    # Frozen per-check budget profile (issue #571). Snapshots written before profiles existed
    # omit it and replay under the legacy single-effort selection.
    budget_profile: SemanticBudgetProfile = LEGACY_SEMANTIC_BUDGET_PROFILE


def _binding_json(binding: ProviderBinding) -> dict[str, CanonicalJsonValue]:
    return {
        "provider_id": binding.provider_id,
        "model_id": binding.model_id,
        "endpoint_profile_id": binding.endpoint_profile_id,
        "endpoint_profile_version": binding.endpoint_profile_version,
        "transport": binding.transport,
    }


def _execution_json(execution: _SemanticExecution) -> dict[str, CanonicalJsonValue]:
    plan = execution.fallback_plan
    pairing: CanonicalJsonValue = None
    if plan is not None:
        pairing = {
            "primary": {
                "provider_id": plan.primary.provider_id,
                "model_id": plan.primary.model_id,
                "endpoint_profile_id": plan.primary.endpoint_profile_id,
                "endpoint_profile_version": plan.primary.endpoint_profile_version,
                "max_retries": plan.primary.max_retries,
            },
            "fallback_max_retries": plan.fallback.max_retries,
            "primary_predispatch_reason": (
                None
                if plan.primary_predispatch_reason is None
                else plan.primary_predispatch_reason.value
            ),
        }
    return {
        "provider": _binding_json(execution.provider),
        "fallback_binding": (
            None
            if execution.fallback_binding is None
            else _binding_json(execution.fallback_binding)
        ),
        "fallback_plan": pairing,
        "max_retries": execution.max_retries,
        "primary_expires_at": format_rfc3339_millis(execution.primary_expires_at),
        "expires_at": format_rfc3339_millis(execution.expires_at),
        "fallback_timeout_seconds": int(execution.fallback_timeout_seconds),
        "budget_profile": execution.budget_profile,
    }


def _execution_from_json(value: object) -> _SemanticExecution:
    def row(value: object) -> dict[str, object]:
        if type(value) is not dict:
            raise ValueError("semantic_execution_invalid")
        return cast(dict[str, object], value)

    def text(value: object) -> str:
        if type(value) is not str:
            raise ValueError("semantic_execution_invalid")
        return value

    def retries(value: object) -> int:
        if type(value) is not int or not 0 <= value <= 2:
            raise ValueError("semantic_execution_invalid")
        return value

    def binding(value: object) -> ProviderBinding:
        source = row(value)
        return ProviderBinding(
            text(source["provider_id"]),
            text(source["model_id"]),
            text(source["endpoint_profile_id"]),
            text(source["endpoint_profile_version"]),
            cast(Literal["external", "local_af_unix"], text(source["transport"])),
        )

    source = row(value)
    provider = binding(source["provider"])
    fallback = None if source["fallback_binding"] is None else binding(source["fallback_binding"])
    max_retries = retries(source["max_retries"])
    plan = None
    if source["fallback_plan"] is not None:
        pair = row(source["fallback_plan"])
        primary = row(pair["primary"])
        if fallback is None:
            raise ValueError("semantic_execution_invalid")
        reason = pair["primary_predispatch_reason"]
        if reason not in (None, SemanticReason.CREDENTIAL_UNAVAILABLE.value):
            raise ValueError("semantic_execution_invalid")
        plan = SemanticFallbackPlan(
            SemanticEndpointPlan(
                "primary",
                text(primary["provider_id"]),
                text(primary["model_id"]),
                text(primary["endpoint_profile_id"]),
                text(primary["endpoint_profile_version"]),
                retries(primary["max_retries"]),
            ),
            SemanticEndpointPlan(
                "fallback",
                fallback.provider_id,
                fallback.model_id,
                fallback.endpoint_profile_id,
                fallback.endpoint_profile_version,
                retries(pair["fallback_max_retries"]),
            ),
            None if reason is None else SemanticReason.CREDENTIAL_UNAVAILABLE,
        )
        if plan.primary.max_retries != max_retries:
            raise ValueError("semantic_execution_invalid")
    primary_expires_at = parse_rfc3339_millis(source["primary_expires_at"])
    expires_at = parse_rfc3339_millis(source["expires_at"])
    if primary_expires_at > expires_at:
        raise ValueError("semantic_execution_invalid")
    fallback_timeout = source["fallback_timeout_seconds"]
    if type(fallback_timeout) is not int or not 1 <= fallback_timeout <= 3600:
        raise ValueError("semantic_execution_invalid")
    try:
        budget_profile = (
            LEGACY_SEMANTIC_BUDGET_PROFILE
            if "budget_profile" not in source
            else parse_semantic_budget_profile(source["budget_profile"])
        )
    except ValueError:
        raise ValueError("semantic_execution_invalid") from None
    return _SemanticExecution(
        provider,
        fallback,
        plan,
        max_retries,
        primary_expires_at,
        expires_at,
        float(fallback_timeout),
        budget_profile,
    )


async def _read_semantic_execution(
    runtime: TaskRuntime,
    ref: ObjectRef,
) -> tuple[_SemanticExecution | None, str, str, object | None, str | None]:
    """The frozen execution, case identity and check-time change pointer of one job's case.

    The last value is the case digest of the check's own first review when this job is an
    in-check follow-up round (issue #1047), else ``None``.
    """

    from yoetz.protocol.canonical import strict_json_parse

    resolved = await runtime.objects.resolve_verified(ref.object_id, ref.envelope_digest)
    payload = b"".join([chunk async for chunk in runtime.objects.open_verified(resolved)])
    parsed = strict_json_parse(payload)
    if type(parsed) is not dict:
        raise ValueError("semantic_execution_invalid")
    body = cast(dict[str, object], parsed)
    # Legacy pending cases have no frozen endpoint authority. Never retrofit today's pairing.
    if body.get("schema") not in {"yoetz.semantic-case/1", "yoetz.semantic-case/2"}:
        raise ValueError("semantic_execution_unavailable")
    case_id, case_digest = body.get("case_id"), body.get("case_digest")
    if type(case_id) is not str or type(case_digest) is not str:
        raise ValueError("semantic_execution_invalid")
    execution = (
        None
        if body["schema"] == "yoetz.semantic-case/1"
        else _execution_from_json(body["execution"])
    )
    follow_up = body.get("follow_up")
    base_digest: str | None = None
    if follow_up is not None:
        base = (
            cast(dict[str, object], follow_up).get("base_case_digest")
            if type(follow_up) is dict
            else None
        )
        if type(base) is not str or execution is None:
            raise ValueError("semantic_execution_invalid")
        base_digest = base
    # Absent on jobs created before ADR-031 or without a trusted workspace source: such a job
    # rebuilds its case without a check-time change, exactly as it was first built.
    return execution, case_id, case_digest, body.get("check_change"), base_digest


def _without_provider_provenance(
    status: SemanticStatus, reason: SemanticReason
) -> tuple[SemanticStatus, SemanticReason]:
    """Keep provenance-free outcomes valid without inventing a provider result."""
    try:
        validate_semantic_provenance_binding(status, reason, None, None)
    except ProtocolValueError:
        return SemanticStatus.UNAVAILABLE, SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN
    return status, reason


async def _finish_legacy_semantic_job(
    runtime: TaskRuntime,
    frozen: FrozenCase,
    *,
    max_retries: int,
    on_lease_renewed: Callable[[object], None],
) -> FinalSemanticEvaluation:
    """Recover old terminal results; retire unfrozen pending execution without dispatch."""
    from yoetz.ports.ledger import AttemptOutcome

    ledger = runtime.ledger
    lease = await ledger.renew_leases(frozen.lease)
    on_lease_renewed(lease)
    job = await ledger.load_semantic_job(lease.writer_id, lease.operation_id)
    if job is None:
        raise ValueError("semantic_execution_unavailable")
    wait = await ledger.load_disclosure_wait(lease.writer_id, lease.operation_id)
    if job.state == "leased":
        handle = await ledger.claim_semantic_job(lease, job.job_id)
        reason = (
            SemanticReason.COORDINATOR_FAILURE
            if wait is not None
            and wait.attempt_id == handle.attempt_id
            and wait.state == "awaiting"
            else SemanticReason.OUTCOME_UNKNOWN
        )
        await ledger.record_attempt_outcome(handle, AttemptOutcome.FAILED, terminal_code=reason)
    elif job.state == "queued":
        await ledger.fail_semantic_job(lease, job.job_id, SemanticReason.COORDINATOR_FAILURE)
    job = await ledger.load_semantic_job(lease.writer_id, lease.operation_id)
    assert job is not None
    if wait is not None and wait.job_id == job.job_id and wait.state == "awaiting":
        await ledger.resolve_disclosure_wait(job.job_id)
    attempts = await ledger.list_semantic_attempts(job.job_id)
    accounting = attempt_accounting_from_rows(job, attempts, max_retries=max_retries)
    if job.state == "succeeded":
        selected = await _recover_selected_evaluation(runtime, job)
        if selected is not None:
            return replace(selected, attempt_accounting=accounting, operation_lease=lease)
    reason = job.terminal_code or SemanticReason.COORDINATOR_FAILURE
    if reason is SemanticReason.SEMANTIC_COMPLETED:
        reason = SemanticReason.COORDINATOR_FAILURE
    status = status_for_semantic_reason(reason)
    latest = max(attempts, key=lambda attempt: attempt.attempt_ordinal, default=None)
    if latest is not None and latest.result_object_ref is not None:
        recovered = await _recover_response_evaluation(runtime, latest.result_object_ref)
        if recovered is not None and recovered.status is status and recovered.reason is reason:
            return replace(recovered, attempt_accounting=accounting, operation_lease=lease)
    status, reason = _without_provider_provenance(status, reason)
    return FinalSemanticEvaluation(
        status,
        reason,
        attempt_accounting=accounting,
        operation_lease=lease,
    )


async def _publish_semantic_case_object(
    runtime: TaskRuntime,
    *,
    case_digest: str,
    case_id: str,
    dependency_digest: str,
    clock: ClockPort,
    execution: _SemanticExecution,
    check_change: CanonicalJsonValue | None = None,
    follow_up: tuple[str, int] | None = None,
) -> ObjectRef:
    """Persist a structural SEMANTIC_CASE object bound into the durable job row.

    ``check_change`` is the pointer to the one check-time change object (ADR-031), or the record
    that it was unavailable; the change's content stays in its own object. ``follow_up`` is the
    check's first case digest and the round, for an in-check follow-up job (issue #1047).
    """

    body: dict[str, CanonicalJsonValue] = {
        "schema": "yoetz.semantic-case/2",
        "case_id": case_id,
        "case_digest": case_digest,
        "dependency_digest": dependency_digest,
        "execution": _execution_json(execution),
    }
    if check_change is not None:
        body["check_change"] = check_change
    if follow_up is not None:
        body["follow_up"] = {"base_case_digest": follow_up[0], "round": follow_up[1]}
    payload = canonical_encode(cast(CanonicalJsonValue, body))
    staged = await runtime.objects.stage(
        ObjectSource(data=payload, declared_size=len(payload)),
        ObjectMetadata(
            ObjectKind.SEMANTIC_CASE,
            "application/json",
            runtime.task_id,
            clock.now_utc(),
        ),
    )
    return await runtime.objects.finalize(staged)


def _packet_view_gaps(view: SemanticPacketView) -> frozenset[str]:
    """Gaps the packet the reviewer was shown adds to the check (issue #905).

    Prior-finding rows envelope bounding removed are disclosed like any other cut.
    """

    if view.prior_findings_trimmed:
        return frozenset({SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP})
    return frozenset()


def _judgment_to_response_json(judgment: object) -> dict[str, CanonicalJsonValue]:
    """Encode a SemanticJudgment into the durable SEMANTIC_RESPONSE wire object."""

    from yoetz.ports.semantic import ReviewerChallenge, SemanticJudgment

    if type(judgment) is not SemanticJudgment:
        raise TypeError("semantic_judgment_required")
    challenges: list[CanonicalJsonValue] = []
    for item in judgment.challenges:
        if type(item) is not ReviewerChallenge:
            raise TypeError("semantic_judgment_required")
        challenge: dict[str, CanonicalJsonValue] = {
            "finding_kind": item.finding_kind.value,
            "summary": item.summary,
            "cited_refs": list(item.cited_refs),
            "discrepancy": item.discrepancy,
            "alternative_interpretation": item.alternative_interpretation,
            "message_to_main_agent": item.message_to_main_agent,
            "requested_next_step": item.requested_next_step,
            "uncertainty": item.uncertainty,
        }
        if item.snippet is not None:
            challenge["snippet"] = item.snippet
        # Emitted only when present, so earlier stored judgments keep their bytes (issue #980).
        if item.restates is not None:
            challenge["restates"] = item.restates
        challenges.append(challenge)
    body: dict[str, CanonicalJsonValue] = {
        "conclusion": judgment.conclusion,
        "reviewer_challenges": challenges,
        "review_summary": judgment.review_summary,
        "verified": [
            {
                "requirement_or_claim": item.requirement_or_claim,
                "verdict": item.verdict,
                "cited_refs": list(item.cited_refs),
                **({} if item.snippet is None else {"snippet": item.snippet}),
            }
            for item in judgment.verified
        ],
    }
    # Emitted only when present, so a judgment without verdicts keeps its earlier stored bytes.
    if judgment.prior_finding_verdicts:
        body["prior_finding_verdicts"] = [
            {
                "cited_refs": list(item.cited_refs),
                "finding_id": item.finding_id,
                "verdict": item.verdict,
            }
            for item in judgment.prior_finding_verdicts
        ]
    if judgment.prior_finding_verdicts_dropped:
        body["prior_finding_verdicts_dropped"] = judgment.prior_finding_verdicts_dropped
    if judgment.verified_dropped:
        body["verified_dropped"] = judgment.verified_dropped
    if judgment.missing_for_assessment:
        # Issue #907: the named missing items, reviewer reason included, live only in this
        # encrypted durable response object; the check record keeps the structural fields.
        body["missing_for_assessment"] = [
            {"kind": item.kind, "target_refs": list(item.target_refs), "reason": item.reason}
            for item in judgment.missing_for_assessment
        ]
    return body


def _judgment_from_response_json(value: object) -> object:
    """Decode a durable SEMANTIC_RESPONSE judgment object into SemanticJudgment."""

    from yoetz.domain.findings import FindingKind
    from yoetz.ports.semantic import (
        MissingForAssessment,
        MissingForAssessmentKind,
        PriorFindingVerdict,
        PriorFindingVerdictKind,
        ReviewerChallenge,
        ReviewerNextStep,
        SemanticConclusion,
        SemanticJudgment,
        VerifiedReviewItem,
        VerifiedReviewVerdict,
    )

    if type(value) is not dict:
        raise ValueError("semantic_response_judgment_invalid")
    source = cast(dict[str, object], value)
    conclusion_raw = source.get("conclusion")
    raw_challenges = source.get("reviewer_challenges")
    # Backward-compatible with the earlier structural-only challenge_count form.
    if raw_challenges is None and "challenge_count" in source:
        if conclusion_raw == "challenges_returned":
            raise ValueError("semantic_response_judgment_incomplete")
        if type(conclusion_raw) is not str:
            raise ValueError("semantic_response_judgment_invalid")
        return SemanticJudgment(cast(SemanticConclusion, conclusion_raw), ())
    if type(conclusion_raw) is not str or type(raw_challenges) is not list:
        raise ValueError("semantic_response_judgment_invalid")
    challenges: list[ReviewerChallenge] = []
    for item in cast(list[object], raw_challenges):
        if type(item) is not dict:
            raise ValueError("semantic_response_judgment_invalid")
        row = cast(dict[str, object], item)
        cited = row.get("cited_refs")
        if type(cited) is not list or any(
            type(ref) is not str for ref in cast(list[object], cited)
        ):
            raise ValueError("semantic_response_judgment_invalid")
        next_step = row.get("requested_next_step")
        if type(next_step) is not str:
            raise ValueError("semantic_response_judgment_invalid")
        try:
            kind = FindingKind(cast(str, row["finding_kind"]))
            snippet = row.get("snippet")
            if snippet is not None and type(snippet) is not str:
                raise ValueError("semantic_response_judgment_invalid")
            restates = row.get("restates")
            if restates is not None and type(restates) is not str:
                raise ValueError("semantic_response_judgment_invalid")
            challenges.append(
                ReviewerChallenge(
                    kind,
                    cast(str, row["summary"]),
                    tuple(cast(list[str], cited)),
                    cast(str, row["discrepancy"]),
                    cast(str, row["alternative_interpretation"]),
                    cast(str, row["message_to_main_agent"]),
                    cast(ReviewerNextStep, next_step),
                    cast(str, row["uncertainty"]),
                    snippet,
                    restates,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("semantic_response_judgment_invalid") from exc
    raw_verdicts = source.get("prior_finding_verdicts", [])
    if type(raw_verdicts) is not list:
        raise ValueError("semantic_response_judgment_invalid")
    verdicts: list[PriorFindingVerdict] = []
    for item in cast(list[object], raw_verdicts):
        if type(item) is not dict:
            raise ValueError("semantic_response_judgment_invalid")
        row = cast(dict[str, object], item)
        cited = row.get("cited_refs")
        if type(cited) is not list:
            raise ValueError("semantic_response_judgment_invalid")
        try:
            verdicts.append(
                PriorFindingVerdict(
                    cast(str, row["finding_id"]),
                    cast(PriorFindingVerdictKind, row["verdict"]),
                    tuple(cast(list[str], cited)),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("semantic_response_judgment_invalid") from exc
    dropped = source.get("prior_finding_verdicts_dropped", 0)
    # Responses recorded before issue #907 carry no missing items and decode with none.
    missing: list[MissingForAssessment] = []
    raw_missing = source.get("missing_for_assessment", [])
    if type(raw_missing) is not list:
        raise ValueError("semantic_response_judgment_invalid")
    for item in cast(list[object], raw_missing):
        if type(item) is not dict:
            raise ValueError("semantic_response_judgment_invalid")
        row = cast(dict[str, object], item)
        targets = row.get("target_refs")
        if type(targets) is not list or any(
            type(ref) is not str for ref in cast(list[object], targets)
        ):
            raise ValueError("semantic_response_judgment_invalid")
        try:
            missing.append(
                MissingForAssessment(
                    cast(MissingForAssessmentKind, row["kind"]),
                    tuple(cast(list[str], targets)),
                    cast(str, row["reason"]),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("semantic_response_judgment_invalid") from exc
    raw_verified = source.get("verified", [])
    if type(raw_verified) is not list:
        raise ValueError("semantic_response_judgment_invalid")
    verified: list[VerifiedReviewItem] = []
    for item in cast(list[object], raw_verified):
        if type(item) is not dict:
            raise ValueError("semantic_response_judgment_invalid")
        row = cast(dict[str, object], item)
        cited = row.get("cited_refs")
        if type(cited) is not list or any(
            type(ref) is not str for ref in cast(list[object], cited)
        ):
            raise ValueError("semantic_response_judgment_invalid")
        snippet = row.get("snippet")
        if snippet is not None and type(snippet) is not str:
            raise ValueError("semantic_response_judgment_invalid")
        try:
            verified.append(
                VerifiedReviewItem(
                    cast(str, row["requirement_or_claim"]),
                    cast(VerifiedReviewVerdict, row["verdict"]),
                    tuple(cast(list[str], cited)),
                    snippet,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("semantic_response_judgment_invalid") from exc
    review_summary = source.get("review_summary", "No review summary recorded.")
    if type(review_summary) is not str:
        raise ValueError("semantic_response_judgment_invalid")
    try:
        return SemanticJudgment(
            cast(SemanticConclusion, conclusion_raw),
            tuple(challenges),
            tuple(verdicts),
            cast(int, dropped),
            missing_for_assessment=tuple(missing),
            review_summary=review_summary,
            verified=tuple(verified),
            verified_dropped=cast(int, source.get("verified_dropped", 0)),
        )
    except ValueError as exc:
        raise ValueError("semantic_response_judgment_invalid") from exc


async def _publish_semantic_response_object(
    runtime: TaskRuntime,
    *,
    attempt_id: str,
    evaluation: FinalSemanticEvaluation,
    clock: ClockPort,
) -> ObjectRef:
    """Persist SEMANTIC_RESPONSE facts (full judgment + provenance; no raw provider text)."""

    body: dict[str, CanonicalJsonValue] = {
        "schema": "yoetz.semantic-response/1",
        "attempt_id": attempt_id,
        "status": evaluation.status.value,
        "reason": evaluation.reason.value,
    }
    if evaluation.judgment is not None:
        body["judgment"] = _judgment_to_response_json(evaluation.judgment)
    if evaluation.provenance is not None:
        body["provenance"] = cast(
            CanonicalJsonValue, dict(semantic_provenance_to_json(evaluation.provenance).items())
        )
    if evaluation.case_included_refs is not None:
        # What the sent packet carried (#904), so a recovered selection records the same fact.
        body["disclosed_content_refs"] = cast(
            CanonicalJsonValue, sorted(evaluation.case_included_refs, key=str.encode)
        )
    if evaluation.case_withheld_refs is not None:
        # tb4n1 D1: refs the sent packet named but withheld for room or policy, so a recovered
        # check classifies a reviewer's missing item the same way.
        body["withheld_content_refs"] = cast(
            CanonicalJsonValue, sorted(evaluation.case_withheld_refs, key=str.encode)
        )
    if evaluation.case_privacy_withheld_refs:
        body["privacy_withheld_content_refs"] = cast(
            CanonicalJsonValue, sorted(evaluation.case_privacy_withheld_refs, key=str.encode)
        )
    if evaluation.semantic_withheld_item_ids:
        # Keep only bounded opaque identities in the durable response.  Matched bytes and source
        # prose stay in the encrypted proposal/case path and never enter this recovery object.
        body["semantic_withheld_item_ids"] = cast(
            CanonicalJsonValue,
            list(sorted(evaluation.semantic_withheld_item_ids, key=str.encode)),
        )
    if evaluation.semantic_redacted_values:
        # PL2-1: item refs and line numbers only, so recovery reports the same fact.
        body["semantic_redacted_values"] = cast(
            CanonicalJsonValue,
            [item.as_wire() for item in evaluation.semantic_redacted_values],
        )
    if evaluation.provider_input_manifest is not None:
        body["provider_input_manifest"] = cast(
            CanonicalJsonValue, dict(evaluation.provider_input_manifest.items())
        )
    if evaluation.provider_input_manifest_failure is not None:
        body["provider_input_manifest_failure"] = evaluation.provider_input_manifest_failure
    payload = canonical_encode(cast(CanonicalJsonValue, body))
    staged = await runtime.objects.stage(
        ObjectSource(data=payload, declared_size=len(payload)),
        ObjectMetadata(
            ObjectKind.SEMANTIC_RESPONSE,
            "application/json",
            runtime.task_id,
            clock.now_utc(),
        ),
    )
    return await runtime.objects.finalize(staged)


def _semantic_response_withheld_item_ids(
    body: Mapping[str, object],
) -> tuple[str, ...] | None:
    """Decode the optional bounded omission identities from a response object."""

    raw = body.get("semantic_withheld_item_ids")
    if raw is None:
        return ()
    if type(raw) is not list:
        return None
    values = tuple(item for item in cast(list[object], raw) if type(item) is str)
    if len(values) != len(cast(list[object], raw)):
        return None
    if (
        len(values) > 64
        or any(not _valid_opaque_item_id(item) for item in values)
        or values != tuple(sorted(set(values), key=str.encode))
    ):
        return None
    return values


def _semantic_response_redacted_values(
    body: Mapping[str, object],
) -> tuple[SemanticRedactedValue, ...] | None:
    """Decode the optional PL2-1 entries; ``None`` marks a corrupt response object."""

    raw = body.get("semantic_redacted_values")
    if raw is None:
        return ()
    try:
        return semantic_redacted_values_from_wire(raw)
    except ValueError:
        return None


def _valid_opaque_item_id(value: object) -> bool:
    try:
        validate_opaque_item_id(value)
    except ValueError:
        return False
    return True


async def _recover_selected_evaluation(
    runtime: TaskRuntime,
    job: object,
) -> FinalSemanticEvaluation | None:
    """Load judgment/provenance from the durable selected SEMANTIC_RESPONSE object."""

    from yoetz.ports.ledger import SemanticJobRecord as _Job

    if type(job) is not _Job:
        return None
    ref = job.selected_result_object_ref
    if ref is None:
        return None
    return await _recover_response_evaluation(runtime, ref)


async def _recover_response_evaluation(
    runtime: TaskRuntime, ref: ObjectRef
) -> FinalSemanticEvaluation | None:
    from yoetz.application.semantic_case import (  # pyright: ignore[reportPrivateUsage]
        _decode_review_input_manifest,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.findings import semantic_provenance_from_json
    from yoetz.ports.semantic import SemanticJudgment
    from yoetz.protocol.canonical import strict_json_parse

    try:
        resolved = await runtime.objects.resolve_verified(ref.object_id, ref.envelope_digest)
        payload = b"".join([chunk async for chunk in runtime.objects.open_verified(resolved)])
        parsed = strict_json_parse(payload)
    except KeyError, OSError, TypeError, ValueError:
        return None
    if type(parsed) is not dict:
        return None
    body = cast(dict[str, object], parsed)
    withheld_item_ids = _semantic_response_withheld_item_ids(body)
    if withheld_item_ids is None:
        return None
    redacted_values = _semantic_response_redacted_values(body)
    if redacted_values is None:
        return None
    try:
        status = SemanticStatus(cast(str, body["status"]))
        reason = SemanticReason(cast(str, body["reason"]))
    except KeyError, TypeError, ValueError:
        return None
    judgment = None
    provenance = None
    raw_judgment = body.get("judgment")
    if raw_judgment is not None:
        try:
            decoded = _judgment_from_response_json(raw_judgment)
        except TypeError, ValueError:
            return None
        if type(decoded) is SemanticJudgment:
            judgment = decoded
    raw_provenance = body.get("provenance")
    if raw_provenance is not None:
        try:
            from yoetz.domain.values import freeze_json

            provenance = semantic_provenance_from_json(freeze_json(raw_provenance))
        except TypeError, ValueError:
            return None
    if status is SemanticStatus.SUCCEEDED and (judgment is None or provenance is None):
        return None
    disclosed: frozenset[str] | None = None
    raw_disclosed = body.get("disclosed_content_refs")
    if type(raw_disclosed) is list:
        refs = cast(list[object], raw_disclosed)
        if all(type(ref) is str for ref in refs):
            disclosed = frozenset(cast(list[str], refs))
    withheld_refs: frozenset[str] | None = None
    raw_withheld = body.get("withheld_content_refs")
    if type(raw_withheld) is list:
        withheld_list = cast(list[object], raw_withheld)
        if all(type(ref) is str for ref in withheld_list):
            withheld_refs = frozenset(cast(list[str], withheld_list))
    privacy_refs: frozenset[str] = frozenset()
    raw_privacy = body.get("privacy_withheld_content_refs")
    if type(raw_privacy) is list:
        privacy_list = cast(list[object], raw_privacy)
        if all(type(ref) is str for ref in privacy_list):
            privacy_refs = frozenset(cast(list[str], privacy_list))
    provider_manifest = None
    provider_manifest_failure: str | None = None
    raw_provider_manifest = body.get("provider_input_manifest")
    raw_provider_failure = body.get("provider_input_manifest_failure")
    if status is SemanticStatus.SUCCEEDED:
        if raw_provider_failure is not None:
            if (
                type(raw_provider_failure) is str
                and raw_provider_failure in SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES
                and raw_provider_manifest is None
            ):
                provider_manifest_failure = raw_provider_failure
            else:
                provider_manifest_failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP
        elif raw_provider_manifest is None:
            # Older response objects may predate the provider-bound field.  They remain readable,
            # but recovery cannot prove what the provider received.
            provider_manifest_failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP
        elif isinstance(raw_provider_manifest, dict):
            try:
                from yoetz.domain.values import JsonObject, freeze_json

                frozen_provider = freeze_json(cast(CanonicalJsonValue, raw_provider_manifest))
                if (
                    type(frozen_provider) is JsonObject
                    and _decode_review_input_manifest(
                        frozen_provider, expected_phase="provider_bound"
                    )
                    is not None
                ):
                    provider_manifest = frozen_provider
                else:
                    provider_manifest_failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP
            except TypeError, ValueError:
                provider_manifest_failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP
    else:
        provider_manifest_failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP
    case_content_gaps = tuple(
        sorted(
            (
                *(
                    (SEMANTIC_REVIEW_VALUE_REDACTED_GAP,)
                    if _provider_manifest_has_redaction(provider_manifest)
                    else ()
                ),
                *((SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,) if withheld_item_ids else ()),
            ),
            key=str.encode,
        )
    )
    return FinalSemanticEvaluation(
        status,
        reason,
        judgment=judgment,
        provenance=provenance,
        case_included_refs=disclosed,
        case_withheld_refs=withheld_refs,
        case_privacy_withheld_refs=privacy_refs,
        semantic_withheld_item_ids=withheld_item_ids,
        semantic_redacted_values=redacted_values,
        provider_input_manifest=provider_manifest,
        provider_input_manifest_failure=provider_manifest_failure,
        provider_input_text_by_ref=None,
        case_content_gaps=case_content_gaps,
    )


async def _workspace_root_for_runtime(runtime: TaskRuntime | None) -> str | None:
    """The absolute workspace path the task's session opened with, or ``None``.

    Issue #907: a repeated missing-item request anchors absolute paths the agent names to this
    root. It is compared in process only, never recorded, logged or sent.
    """

    if runtime is None:
        return None
    try:
        async for record in runtime.ledger.load_events(runtime.session_id):
            if isinstance(record.payload, SessionOpenedPayload):
                root = record.payload.workspace_ref
                return root if root is not None and os.path.isabs(root) else None
    except Exception:
        return None
    return None


def _observation_workspace_for_runtime(runtime: TaskRuntime) -> str | None:
    """Resolve the task's observation workspace through its durable session route.

    ``TaskRoute.repository_privacy_commitment`` authorizes egress and is deliberately a
    different commitment domain from the observation store's workspace key.  The latter is
    selected only by the durable session route, then checked against the exact runtime task
    before it is handed to the local consent fence.  An unavailable or contradictory route is
    an observation-content gap, never a reason to try the privacy commitment as a fallback.
    """

    observation = runtime.observation
    if observation is None:
        return None
    workspace_lookup = getattr(observation, "workspace_for_yoetz_session", None)
    route_lookup = getattr(observation, "observation_route_for_session", None)
    if not callable(workspace_lookup) or not callable(route_lookup):
        return None
    try:
        workspace = workspace_lookup(runtime.session_id)
    except Exception:
        return None
    if type(workspace) is not str:
        return None
    try:
        validate_commitment(workspace)
    except TypeError, ValueError:
        return None
    try:
        route = route_lookup(workspace=workspace, yoetz_session_id=runtime.session_id)
    except Exception:
        return None
    if type(route) is not tuple:
        return None
    route_values = cast(tuple[object, ...], route)
    if (
        len(route_values) != 3
        or type(route_values[0]) is not str
        or type(route_values[1]) is not str
        or type(route_values[2]) is not bool
        or route_values[1] != runtime.task_id
    ):
        return None
    try:
        validate_commitment(route_values[0])
    except TypeError, ValueError:
        return None
    return workspace


async def _run_capture_inventory_joined[ResultT](
    call: Callable[[], ResultT], *, operation: str
) -> ResultT:
    """Keep the executor future owned until metadata/publication actually settles.

    READY teardown may cancel all Tasks, including a to_thread intermediary.
    Await the executor Future directly so that cancellation of such a Task
    cannot orphan an active proof mutation and release capture exclusion early.
    """

    worker = asyncio.get_running_loop().run_in_executor(
        None, partial(contextvars.copy_context().run, call)
    )
    try:
        await asyncio.wait((worker,))
        return worker.result()
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.wait((worker,))
            except asyncio.CancelledError:
                continue
        try:
            worker.result()
        except BaseException as worker_error:
            if not isinstance(worker_error, asyncio.CancelledError):
                record_unexpected_exception_without_raising(
                    worker_error,
                    component="service.ready_composition",
                    operation=operation,
                )
        raise


async def _bootstrap_capture_reservations(
    workspace: str,
    current_runtime: TaskRuntime,
    current_store: TaskObservationPort,
    *,
    catalog: StartCatalogPort,
    runtime: BundleRuntimePort,
    local_observation: LocalObservationStore,
    clock: ClockPort,
    generation_is_current: Callable[[], bool],
) -> bool:
    """Read the complete catalog inventory before central admission.

    The coordinator invokes this callback while its process-wide capture
    lock is held.  The current route's repository commitment scopes the
    inventory; matching routes are all accounted for, while an unreadable
    or inactive route fails closed instead of being silently omitted.
    """

    try:
        if not generation_is_current():
            raise ValueError("capture_generation_changed")
        current_route = await catalog.resolve_route(current_runtime.session_id)
        if (
            current_route is None
            or current_route.state is not TaskRouteState.ACTIVE
            or current_route.task_id != current_runtime.task_id
            or current_route.repository_privacy_commitment is None
        ):
            raise ValueError("capture_current_route_unavailable")
        repository = current_route.repository_privacy_commitment
        recovery_routes = getattr(catalog, "recovery_routes", None)
        if not callable(recovery_routes):
            raise ValueError("capture_catalog_inventory_unavailable")
        if not generation_is_current():
            raise ValueError("capture_generation_changed")
        raw_routes = await cast(Callable[[], Awaitable[tuple[TaskRoute, ...]]], recovery_routes)()
        if not generation_is_current():
            raise ValueError("capture_generation_changed")
        if type(raw_routes) is not tuple:
            raise ValueError("capture_catalog_inventory_invalid")
        if any(type(route) is not TaskRoute for route in raw_routes):
            raise ValueError("capture_catalog_inventory_invalid")
        all_routes = raw_routes
        if len({route.task_id for route in all_routes}) != len(all_routes):
            raise ValueError("capture_catalog_inventory_duplicate")
        routes = tuple(
            route
            for route in all_routes
            if route.repository_privacy_commitment in {repository, None}
        )
        if not routes or len(routes) > 256:
            raise ValueError("capture_catalog_inventory_incomplete")
        if any(route.state is not TaskRouteState.ACTIVE for route in routes):
            raise ValueError("capture_catalog_inventory_inactive")
        if current_route.task_id not in {route.task_id for route in routes}:
            raise ValueError("capture_catalog_inventory_incomplete")
        inventory: dict[str, ObservationCaptureBacklog] = {}
        ticket_ids_by_task: dict[str, tuple[str, ...]] = {}
        for route in sorted(routes, key=lambda item: item.task_id.encode()):
            task_runtime: TaskRuntime | None = None
            release = False
            try:
                if route.task_id == current_runtime.task_id:
                    task_runtime = current_runtime
                    task_store = current_store
                else:
                    binding = await catalog.session_binding(route.session_id)
                    if (
                        binding is None
                        or binding.task_id != route.task_id
                        or binding.session_id != route.session_id
                    ):
                        raise ValueError("capture_route_binding_unavailable")
                    task_runtime = await runtime.route(
                        RouteCommand(
                            session_id=route.session_id,
                            writer_id=binding.writer_id,
                            access=RouteAccess.WRITE,
                            required_capabilities=frozenset({RuntimeCapability.WRITE}),
                        )
                    )
                    release = True
                    task_store = task_runtime.observation
                if (
                    task_runtime.task_id != route.task_id
                    or task_runtime.session_id != route.session_id
                ):
                    raise ValueError("capture_task_route_changed")
                if task_store is None:
                    raise ValueError("capture_task_observation_unavailable")
                reader = getattr(task_store, "capture_backlog", None)
                if not callable(reader):
                    raise ValueError("capture_task_backlog_unavailable")
                # Task metadata adapters are synchronous and may encounter
                # a SQLite busy wait. Keep that wait off the control loop,
                # joining before releasing the runtime on cancellation.
                backlog = await _run_capture_inventory_joined(
                    partial(reader, workspace), operation="capture_inventory_backlog_read_failed"
                )
                if type(backlog) is not ObservationCaptureBacklog:
                    raise ValueError("capture_task_backlog_invalid")
                inventory[route.task_id] = backlog
                list_pending = getattr(task_store, "list_pending_capture_tickets", None)
                if callable(list_pending):
                    raw_tickets = await _run_capture_inventory_joined(
                        partial(list_pending, route.task_id),
                        operation="capture_inventory_ticket_read_failed",
                    )
                    tickets = cast(tuple[object, ...], raw_tickets)
                    if type(raw_tickets) is not tuple or any(
                        type(ticket) is not ObservationCaptureTicket for ticket in tickets
                    ):
                        raise ValueError("capture_task_ticket_inventory_invalid")
                    scoped_ids: list[str] = []
                    typed_tickets = cast(tuple[ObservationCaptureTicket, ...], tickets)
                    for ticket in typed_tickets:
                        if ticket.task_id != route.task_id:
                            raise ValueError("capture_task_ticket_owner_invalid")
                        if ticket.workspace_commitment == workspace:
                            ticket_id = observation_capture_ticket_id(ticket)
                            if ticket_id in scoped_ids:
                                raise ValueError("capture_task_ticket_duplicate")
                            scoped_ids.append(ticket_id)
                    if len(scoped_ids) == backlog.count and all(
                        ticket.workspace_commitment == workspace for ticket in typed_tickets
                    ):
                        ticket_ids_by_task[route.task_id] = tuple(
                            sorted(scoped_ids, key=str.encode)
                        )
            finally:
                if release and task_runtime is not None:
                    with contextlib.suppress(Exception):
                        await runtime.release(task_runtime)
        # Re-read the catalog after all bundle reads.  A route change while
        # the inventory was in flight must not mint a proof for a stale set.
        if not generation_is_current():
            raise ValueError("capture_generation_changed")
        final_raw_routes = await cast(
            Callable[[], Awaitable[tuple[TaskRoute, ...]]], recovery_routes
        )()
        if not generation_is_current():
            raise ValueError("capture_generation_changed")
        if final_raw_routes != raw_routes:
            raise ValueError("capture_catalog_inventory_changed")
        bootstrap = getattr(local_observation, "bootstrap_capture_reservations", None)
        if not callable(bootstrap):
            raise ValueError("capture_bootstrap_unavailable")
        observed_at = timestamp_from_datetime(clock.now_utc())
        return bool(
            await _run_capture_inventory_joined(
                partial(
                    bootstrap,
                    workspace,
                    inventory,
                    observed_at=observed_at,
                    complete=True,
                    proof_guard=generation_is_current,
                    ticket_ids_by_task=ticket_ids_by_task or None,
                ),
                operation="observation_capture_inventory_publish",
            )
        )
    except Exception:
        mark_unknown = getattr(local_observation, "mark_capture_backlog_scope_unknown", None)
        if callable(mark_unknown):
            with contextlib.suppress(Exception):
                await _run_capture_inventory_joined(
                    partial(mark_unknown, workspace),
                    operation="observation_capture_inventory_unknown",
                )
        return False


async def _reconcile_capture_handoffs(
    workspace: str,
    task_ids: tuple[str, ...],
    visit: Callable[[TaskRuntime, TaskObservationPort], Awaitable[int]],
    *,
    catalog: StartCatalogPort,
    runtime: BundleRuntimePort,
    generation_is_current: Callable[[], bool],
) -> bool:
    """Open each task that owns an aged native handoff and reconcile it (#836).

    The coordinator calls this under its capture lock with task identities
    read from the workspace's own capture reservations and task snapshots, so
    no host-session mapping is needed: a handoff left by an ended session is
    still reachable. Every opened runtime must match its active catalog route;
    an unavailable route is reported as incomplete and retried by the next
    sweep. Tickets are only ever tombstoned, never deleted, by ``visit``.
    """

    del workspace  # ``visit`` is already bound to the workspace it reconciles.
    if not generation_is_current():
        return False
    recovery_routes = getattr(catalog, "recovery_routes", None)
    if not callable(recovery_routes):
        return False
    raw_routes = await cast(Callable[[], Awaitable[tuple[TaskRoute, ...]]], recovery_routes)()
    if type(raw_routes) is not tuple:
        return False
    routes = {
        route.task_id: route
        for route in raw_routes
        if type(route) is TaskRoute and route.state is TaskRouteState.ACTIVE
    }
    complete = True
    for candidate_task in task_ids:
        if not generation_is_current():
            return False
        route = routes.get(candidate_task)
        if route is None:
            complete = False
            continue
        task_runtime: TaskRuntime | None = None
        try:
            binding = await catalog.session_binding(route.session_id)
            if (
                binding is None
                or binding.task_id != route.task_id
                or binding.session_id != route.session_id
            ):
                complete = False
                continue
            task_runtime = await runtime.route(
                RouteCommand(
                    session_id=route.session_id,
                    writer_id=binding.writer_id,
                    access=RouteAccess.WRITE,
                    required_capabilities=frozenset({RuntimeCapability.WRITE}),
                )
            )
            store = task_runtime.observation
            if (
                task_runtime.task_id != route.task_id
                or task_runtime.session_id != route.session_id
                or store is None
            ):
                complete = False
                continue
            await visit(task_runtime, store)
        except Exception:
            complete = False
        finally:
            if task_runtime is not None:
                with contextlib.suppress(Exception):
                    await runtime.release(task_runtime)
    return complete


def _follow_up_section_parts(
    case: SemanticCase,
    change: CheckTimeChange | None,
    edit_paths: Mapping[str, frozenset[str]],
    workspace_root: str | None,
    withheld: Sequence[str],
) -> Mapping[str, frozenset[str]]:
    """What a current-diff follow-up could serve from the frozen change, per edit (tb4n5).

    Empty unless this case carries the change and the channel releases repository excerpts.
    In process only.
    """

    if (
        change is None
        or DataCategory.REPOSITORY_EXCERPT.value in withheld
        or not any(item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX) for item in case.items)
    ):
        return {}
    return current_section_parts(change.capture, edit_paths, workspace_root)


def _admitted_follow_up_parts(
    case: SemanticCase, follow_up: ReviewFollowUp, withheld: Sequence[str]
) -> frozenset[str]:
    """The requested new parts admission keeps (tb4n5): rows the bounded envelope's catalog
    keeps, in categories the channel does not withhold, so a round whose new parts admission
    would drop is never sent. A part egress then withholds under a privacy rule is disclosed on
    the sent packet (the provider-bound manifest says ``pending``) and never asked for again."""

    return follow_up_new_parts(
        case,
        follow_up,
        withheld_categories=withheld,
        carried_item_ids=bounded_catalog_item_ids(case),
    )


def _privacy_gated_semantic_evaluator(
    privacy: PrivacyCoordinator,
    clock: ClockPort,
    installation_id: str,
    resolve_provider: Callable[[], Awaitable[ProviderBinding | None]],
    catalog: StartCatalogPort,
    ids: IdPort,
    *,
    timeout_seconds: int = 60,
    max_retries: int = 2,
    resolve_fallback: Callable[[], Awaitable[ProviderBinding | None]] | None = None,
    fallback_timeout_seconds: int = 60,
    fallback_max_retries: int = 2,
    external_runtime_state: Callable[[], str | None] | None = None,
    configured_primary: ProviderBinding | None = None,
    lineage_source_gate: LineageSourceGate | None = None,
    local_observation: object | None = None,
    attention: SemanticAttentionTracker | None = None,
    change_capture: ChangeCapturePort | None = None,
):
    total_timeout = float(max(1, min(int(timeout_seconds), 3600)))
    # The fallback endpoint owns its own deadline share (#582): a primary that spends its whole
    # timeout failing must not leave the fallback with nothing to run in.
    fallback_timeout = float(max(1, min(int(fallback_timeout_seconds), 3600)))

    def _endpoint_plan(
        role: Literal["primary", "fallback"], binding: ProviderBinding, retries: int
    ) -> SemanticEndpointPlan:
        return SemanticEndpointPlan(
            role,
            binding.provider_id,
            binding.model_id,
            binding.endpoint_profile_id,
            binding.endpoint_profile_version,
            int(retries),
        )

    async def _evaluate(
        frozen: FrozenCase,
        findings: tuple[object, ...],
        runtime: TaskRuntime | None = None,
        lineage_evaluation: LineageEvaluation | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
        task_fact_gaps: tuple[str, ...] = (),
        follow_up: ReviewFollowUp | None = None,
    ) -> FinalSemanticEvaluation | None:
        """One review of the frozen case, or one in-check follow-up round of it (issue #1047).

        A follow-up builds the same case with the excerpts the reviewer asked for ranked first,
        under the endpoint, budget profile and check-time change frozen with the check's own
        review job, in a job of its own keyed by its case digest, so recovery finds it again.
        ``None`` means nothing was dispatched: the check has no completed review of its own, or
        the follow-up packet would add nothing earlier packets did not carry.
        """

        from yoetz.ports.ledger import OperationLease as _OpLease

        # Tracked from the top so *every* exit — including the catch-all below — can return the
        # newest lease. The attempt loop renews before it does anything else, which bumps
        # lease_generation; a return without the renewed token leaves the caller holding a stale
        # one, and there is no API to re-acquire your own live lease. The check then fails
        # OPERATION_PENDING and the whole operation is lost rather than recording an honest
        # AI-powered review failure. That is what stranded the 2026-07-30 dogfood run.
        current_lease: list[_OpLease] = [frozen.lease]
        # Bound here too: the catch-all below can be reached before the policy is resolved, and
        # an unbound name there would turn a reportable failure into a second one.
        withheld: tuple[str, ...] = ()
        credential_heuristic_disabled = False
        over_item_limit = False
        reference_scope_reduced = False
        content_gaps: tuple[str, ...] = ()
        unsuppliable: tuple[str, ...] = ()
        check_change_files: CheckChangeShownFiles | None = None

        def _on_lease_renewed(renewed: object) -> None:
            assert type(renewed) is _OpLease
            current_lease[0] = renewed

        try:
            if lineage_evaluation is not None:
                if lineage_source_gate is None or not isinstance(runtime, TaskRuntime):
                    return FinalSemanticEvaluation(
                        SemanticStatus.BLOCKED_BY_POLICY,
                        SemanticReason.SCOPE_NOT_AUTHORIZED,
                    )
                lineage_authority = await authorize_recorded_lineage(
                    runtime.task_id,
                    lineage_evaluation,
                    catalog,
                    lineage_source_gate,
                )
                if not lineage_authority.allowed or lineage_authority.restrictions:
                    record_bounded_event_without_raising(
                        component="semantic_composition",
                        operation="semantic_lineage_authority_blocked",
                        reason=SemanticReason.SCOPE_NOT_AUTHORIZED.value,
                        request_id=frozen.lease.operation_id,
                    )
                    return FinalSemanticEvaluation(
                        SemanticStatus.BLOCKED_BY_POLICY,
                        SemanticReason.SCOPE_NOT_AUTHORIZED,
                    )
            route = await catalog.resolve_route(frozen.lease.session_id)
            if route is None or route.state is not TaskRouteState.ACTIVE:
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_not_dispatched_route_inactive",
                    reason=SemanticReason.PROVIDER_NOT_CONFIGURED.value,
                    request_id=frozen.lease.operation_id,
                )
                return await _semantic_not_configured(frozen, findings)
            repository = route.repository_privacy_commitment
            if repository is None:
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_not_dispatched_repository_scope_unavailable",
                    reason=SemanticReason.SCOPE_NOT_AUTHORIZED.value,
                    request_id=frozen.lease.operation_id,
                )
                return FinalSemanticEvaluation(
                    SemanticStatus.BLOCKED_BY_POLICY,
                    SemanticReason.SCOPE_NOT_AUTHORIZED,
                )
            scope = AuthorizationScope(
                AuthorizationScopeKind.TASK,
                installation_id,
                repository,
                route.task_id,
            )
            typed_findings = tuple(item for item in findings if type(item) is Finding)
            # Resolve the effective selection before repository/provider admission. This is the
            # first full-specification gate: a missing statement must yield a supported input
            # continuation without probing credentials or spending a provider attempt.
            policy_app = getattr(privacy, "policy_application", None)
            if policy_app is None:
                # A coordinator without its policy application cannot establish the policy
                # identity required for a semantic packet.  Preserve the pre-existing
                # fail-closed repository admission behavior for direct/unit coordinators (and
                # for a coordinator that is racing setup); do not manufacture a complete-spec
                # continuation from an unbound policy.
                try:
                    repository_admission = await privacy.admit_repository_grant(scope)
                except Exception:
                    repository_admission = RepositoryGrantAdmission.UNAVAILABLE
                if repository_admission is RepositoryGrantAdmission.MISSING:
                    return FinalSemanticEvaluation(
                        SemanticStatus.AWAITING_HUMAN,
                        SemanticReason.HUMAN_APPROVAL_REQUIRED,
                        continuation=repository_grant_continuation(
                            request_id=frozen.lease.operation_id
                        ),
                    )
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_not_dispatched_repository_scope_unavailable",
                    reason=SemanticReason.SCOPE_NOT_AUTHORIZED.value,
                    request_id=frozen.lease.operation_id,
                )
                return FinalSemanticEvaluation(
                    SemanticStatus.BLOCKED_BY_POLICY,
                    SemanticReason.SCOPE_NOT_AUTHORIZED,
                )
            effective = await policy_app.policy_store.effective_policy(scope)
            policy = effective.policy
            review_profile = policy.review_context_profile
            review_selection = review_selection_for_delivery(policy)
            policy_id = policy.policy_id
            policy_version = str(policy.version)
            withheld = tuple(item.value for item in policy.withheld_review_categories)
            # The owner opt-out (issue #982) is carried to the check so every review that ran
            # under it discloses that possible-credential values were not filtered.
            credential_heuristic_disabled = not policy.credential_heuristic_enforced
            unsuppliable = unsuppliable_missing_kinds(review_selection, withheld)
            if withheld:
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_review_context_categories_withheld",
                    reason=SemanticReason.CONTENT_CATEGORY_NOT_AUTHORIZED.value,
                    request_id=frozen.lease.operation_id,
                )
            preflight = specification_preflight(
                frozen.case.task_statement,
                frozen.case.task_title,
                review_selection,
                required=require_complete_specification,
                channel_sends_task_description=("task_statement" in review_selection.sections),
            )
            if preflight.actionable:
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_suspended_review_input_required",
                    reason="task_statement_not_supplied",
                    request_id=frozen.lease.operation_id,
                )
                return FinalSemanticEvaluation(
                    SemanticStatus.AWAITING_HUMAN,
                    SemanticReason.HUMAN_APPROVAL_REQUIRED,
                    continuation=review_input_continuation(request_id=frozen.lease.operation_id),
                    specification_preflight=preflight,
                )
            # The coordinator owns repository admission under its closure lock. Only an exactly
            # bound missing grant observed while that lock is live can yield a trusted setup
            # continuation. Closure, malformed/mismatched authority, policy failures, and failed
            # reconciliation are terminal no-dispatch states.
            try:
                repository_admission = await privacy.admit_repository_grant(scope)
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="semantic_composition",
                    operation="repository_admission_failed",
                    request_id=frozen.lease.operation_id,
                )
                repository_admission = RepositoryGrantAdmission.UNAVAILABLE
            if repository_admission is RepositoryGrantAdmission.MISSING:
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_suspended_repository_grant_missing",
                    reason=SemanticReason.HUMAN_APPROVAL_REQUIRED.value,
                    request_id=frozen.lease.operation_id,
                )
                return FinalSemanticEvaluation(
                    SemanticStatus.AWAITING_HUMAN,
                    SemanticReason.HUMAN_APPROVAL_REQUIRED,
                    continuation=repository_grant_continuation(
                        request_id=frozen.lease.operation_id
                    ),
                    specification_preflight=preflight,
                )
            if repository_admission is not RepositoryGrantAdmission.GRANTED:
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_not_dispatched_repository_scope_unavailable",
                    reason=SemanticReason.SCOPE_NOT_AUTHORIZED.value,
                    request_id=frozen.lease.operation_id,
                )
                return FinalSemanticEvaluation(
                    SemanticStatus.BLOCKED_BY_POLICY,
                    SemanticReason.SCOPE_NOT_AUTHORIZED,
                )
            # Existing jobs carry the original endpoint/readiness/budget decision in their
            # encrypted case object. Reconciliation above remains live authority; mutable
            # provider resolution must never relabel an already claimed physical attempt.
            job = None
            execution: _SemanticExecution | None = None
            recovered_case_id: str | None = None
            recovered_case_digest: str | None = None
            recovered_check_change: object | None = None
            if runtime is not None:
                job = await runtime.ledger.load_semantic_job(
                    frozen.lease.writer_id, frozen.lease.operation_id
                )
                if job is not None:
                    (
                        execution,
                        recovered_case_id,
                        recovered_case_digest,
                        recovered_check_change,
                        base_case_digest,
                    ) = await _read_semantic_execution(runtime, job.case_object_ref)
                    if base_case_digest is not None:
                        # An in-check follow-up job (issue #1047): the check's own review job is
                        # its base, and every round is rebuilt from what that job froze.
                        job = await runtime.ledger.load_semantic_job(
                            frozen.lease.writer_id,
                            frozen.lease.operation_id,
                            case_digest=base_case_digest,
                        )
                        if job is None:
                            raise ValueError("semantic_follow_up_base_missing")
                        (
                            execution,
                            recovered_case_id,
                            recovered_case_digest,
                            recovered_check_change,
                            _,
                        ) = await _read_semantic_execution(runtime, job.case_object_ref)
                    if follow_up is not None and (execution is None or job.state != "succeeded"):
                        return None
                    if execution is None:
                        return await _finish_legacy_semantic_job(
                            runtime,
                            frozen,
                            max_retries=max_retries,
                            on_lease_renewed=_on_lease_renewed,
                        )
                elif follow_up is not None:
                    # A follow-up answers the check's own completed review; there is none.
                    return None
            if execution is not None:
                provider = execution.provider
                fallback_binding = execution.fallback_binding
                fallback_plan = execution.fallback_plan
                operation_max_retries = execution.max_retries
            else:
                # Re-resolve only after repository-scoped lazy reconciliation. A binding activated
                # after composition takes effect without restart; a revoked grant cannot reach this
                # lookup because activation above fails closed.
                try:
                    provider = await resolve_provider()
                except Exception as exc:
                    record_unexpected_exception_without_raising(
                        exc,
                        component="semantic_composition",
                        operation="semantic_evaluation_failed",
                        request_id=frozen.lease.operation_id,
                    )
                    return FinalSemanticEvaluation(
                        SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE
                    )
                fallback_binding: ProviderBinding | None = None
                if resolve_fallback is not None:
                    try:
                        fallback_binding = await resolve_fallback()
                    except Exception as exc:
                        # An unresolvable fallback must not take the primary down with it: the
                        # single-endpoint path continues exactly as before.
                        record_unexpected_exception_without_raising(
                            exc,
                            component="semantic_composition",
                            operation="semantic_fallback_resolve_failed",
                            request_id=frozen.lease.operation_id,
                        )
                        fallback_binding = None
                if provider is None and fallback_binding is None:
                    _record_external_runtime_state(
                        external_runtime_state, frozen.lease.operation_id
                    )
                    record_bounded_event_without_raising(
                        component="semantic_composition",
                        operation="semantic_not_dispatched_credential_unavailable",
                        reason=SemanticReason.CREDENTIAL_UNAVAILABLE.value,
                        request_id=frozen.lease.operation_id,
                    )
                    return FinalSemanticEvaluation(
                        SemanticStatus.UNAVAILABLE, SemanticReason.CREDENTIAL_UNAVAILABLE
                    )
                fallback_plan: SemanticFallbackPlan | None = None
                if fallback_binding is not None and configured_primary is not None:
                    # A primary that cannot be resolved at all is a pre-dispatch failure the
                    # fallback is licensed to cover; it is named, with zero attempts, in provenance.
                    fallback_plan = SemanticFallbackPlan(
                        _endpoint_plan("primary", provider or configured_primary, max_retries),
                        _endpoint_plan("fallback", fallback_binding, fallback_max_retries),
                        None if provider is not None else SemanticReason.CREDENTIAL_UNAVAILABLE,
                    )
                    if provider is None:
                        _record_external_runtime_state(
                            external_runtime_state, frozen.lease.operation_id
                        )
                        record_bounded_event_without_raising(
                            component="semantic_composition",
                            operation="semantic_primary_unresolved_fallback_engaged",
                            reason=SemanticReason.CREDENTIAL_UNAVAILABLE.value,
                            request_id=frozen.lease.operation_id,
                        )
                # The binding every single-endpoint path below builds against.
                provider = provider if provider is not None else fallback_binding
                assert provider is not None  # one of the two resolved above
                operation_max_retries = max_retries
            # The opt-out reaches only an external reviewer (owner decision, 2026-10-07).
            credential_heuristic_disabled = (
                credential_heuristic_disabled and provider.transport == "external"
            )
            captured_content = ()
            captured_content_scope = None
            captured_content_gaps = ()
            captured_local_fence_generation: str | None = None
            captured_local_fence_profiles: tuple[str, ...] = ()
            captured_local_fence_required = False
            captured_observation_workspace: str | None = None
            if (
                runtime is not None
                and "targeted_excerpts" in review_selection.sections
                and review_selection.max_excerpts > 0
            ):
                captured_observation_workspace = _observation_workspace_for_runtime(runtime)
                if captured_observation_workspace is None:
                    captured_content_gaps = ("content_capture_unavailable",)
                else:
                    try:
                        captured_resolution = await resolve_captured_semantic_content(
                            runtime=runtime,
                            frozen=FrozenCase(frozen.case, current_lease[0]),
                            workspace_commitment=captured_observation_workspace,
                            local_observation=local_observation,
                            max_parts=min(
                                MAX_CAPTURED_SEMANTIC_CONTENT_PARTS,
                                max(16, review_selection.max_excerpts * 16),
                            ),
                            max_total_bytes=MAX_CAPTURED_SEMANTIC_INPUT_BYTES,
                            workspace_root=await _workspace_root_for_runtime(runtime),
                        )
                        captured_content = captured_resolution.content
                        captured_content_scope = captured_resolution.scope
                        captured_content_gaps = captured_resolution.gaps
                        captured_local_fence_generation = captured_resolution.local_fence_generation
                        captured_local_fence_profiles = captured_resolution.local_fence_profiles
                        captured_local_fence_required = captured_resolution.local_fence_required
                    except Exception as exc:
                        # Content is an additive evidence arm. A malformed or unavailable
                        # retained object must leave the local case usable while
                        # carrying an explicit bounded coverage gap into the packet.
                        record_unexpected_exception_without_raising(
                            exc,
                            component="semantic_composition",
                            operation="semantic_content_resolution_failed",
                            request_id=frozen.lease.operation_id,
                        )
                        captured_content_gaps = ("content_capture_unavailable",)
                        captured_local_fence_required = False
            # The check-time change (ADR-031): captured once for a new job, reloaded from the
            # job's own case object on recovery, never re-read from a working tree that moved.
            check_change = CheckChangeOutcome()
            if runtime is not None and check_time_change_selected(review_selection):
                if job is not None:
                    if recovered_check_change is not None:
                        check_change = await recover_check_time_change(
                            runtime, recovered_check_change
                        )
                else:
                    workspace_source = current_check_workspace_source()
                    if workspace_source is not None and change_capture is not None:
                        check_change = await capture_check_time_change(
                            runtime=runtime,
                            source=workspace_source,
                            route_repository_commitment=repository,
                            port=change_capture,
                            clock=clock,
                            request_id=frozen.lease.operation_id,
                            # Declared deliverables first, so a clipped packet keeps them.
                            priority_paths=declared_output_paths(frozen.case.projection),
                            # Read-only task inputs the statement names (#1045), only where the
                            # recipe carries both the statement and repository excerpts.
                            input_paths=(
                                task_input_paths(
                                    frozen.case.projection,
                                    None
                                    if frozen.case.task_statement is None
                                    else frozen.case.task_statement.text,
                                )
                                if carries_task_inputs(review_selection)
                                else ()
                            ),
                        )
            test_edit_gaps = (
                ()
                if check_change.change is None
                else preexisting_test_edits(
                    check_change.change.capture,
                    frozen.case.projection,
                    task_statement_event_id=(
                        None
                        if frozen.case.task_statement is None
                        else frozen.case.task_statement.equivalent_event_ids
                    ),
                ).gaps
            )
            if test_edit_gaps:
                # The aggregate codes are safe to carry into the reviewer packet: paths and
                # content remain inside the encrypted bounded change capture, while the reviewer
                # still sees that pre-existing test edits need scrutiny.
                captured_content_gaps = tuple(
                    sorted(set(captured_content_gaps) | set(test_edit_gaps), key=str.encode)
                )
            if task_fact_gaps:
                # Check-time requested-output facts (#977) are closed codes only; paths stay in
                # the local check result. The closing review (#976) reads them beside the work.
                captured_content_gaps = tuple(
                    sorted(set(captured_content_gaps) | set(task_fact_gaps), key=str.encode)
                )
            workspace_root = await _workspace_root_for_runtime(runtime)
            semantic_case_id = recovered_case_id or ids.new(IdKind.OUTBOUND_CASE)

            def build_case(selection: ReviewSelectionPolicy, gaps: tuple[str, ...]) -> SemanticCase:
                return build_semantic_case(
                    case_id=semantic_case_id,
                    frozen_case=frozen.case,
                    dependency_digest=frozen.lease.dependency_digest,
                    findings=typed_findings,
                    review_context_profile=review_profile,
                    review_selection=selection,
                    policy_id=policy_id,
                    policy_version=policy_version,
                    lineage_evaluation=lineage_evaluation,
                    captured_content=captured_content,
                    captured_content_scope=captured_content_scope,
                    captured_content_gaps=gaps,
                    prepared_byte_ceiling=_semantic_prepared_byte_ceiling(policy),
                    workspace_root=workspace_root,
                    check_time_change=check_change.change,
                    check_time_change_unavailable=check_change.unavailable,
                    check_time_change_unavailable_reason=check_change.reason,
                    final_review=final_review,
                    follow_up=follow_up,
                )

            try:
                # Plan below the channel ceiling before egress would refuse the whole packet: a
                # smaller excerpt budget is a narrowing of the approved selection (issue #907).
                approved_case = build_case(review_selection, tuple(captured_content_gaps))
                semantic_case, planned_selection, ceiling_rounds = plan_under_channel_ceiling(
                    approved_case,
                    review_selection,
                    channel_prepared_limit(policy),
                    lambda selection: build_case(
                        selection, with_ceiling_planning_gap(captured_content_gaps)
                    ),
                    # Size what egress will release to either destination, not the items local
                    # minimization withholds from the channel.
                    channel_admission(policy, (provider, fallback_binding)),
                )
            except SemanticCaseCapacityExceeded as exc:
                # Same pre-dispatch contract as an envelope that cannot be reduced: local
                # findings stay recorded, no job is created, and the caller sees a capacity
                # reason instead of a generic coordinator failure. Lineage keeps its own
                # operation; fixed non-excerpt material over the case bound gets its own too.
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation=(
                        "semantic_not_dispatched_lineage_capacity"
                        if isinstance(exc, LineageSemanticCapacityExceeded)
                        else "semantic_not_dispatched_case_capacity"
                    ),
                    reason=SemanticReason.CASE_CAPACITY_EXCEEDED.value,
                    request_id=frozen.lease.operation_id,
                )
                return FinalSemanticEvaluation(
                    SemanticStatus.FAILED,
                    SemanticReason.CASE_CAPACITY_EXCEEDED,
                    operation_lease=current_lease[0],
                    withheld_review_categories=withheld,
                )
            input_manifest = semantic_case.packet.input_manifest
            # Structural composition diagnostics only: never persist content, paths or hashes.
            # These counters precede privacy minimization and do not certify provider delivery.
            record_bounded_counts_without_raising(
                component="semantic_composition",
                operation="semantic_case_built",
                outcome="built",
                request_id=frozen.lease.operation_id,
                counts={
                    "semantic_capture_parts_resolved": len(captured_content),
                    "semantic_diff_parts_resolved": sum(
                        part.manifest.content_kind.value in {"workspace_diff", "changed_file"}
                        for part in captured_content
                    ),
                    "semantic_excerpts_selected": len(semantic_case.packet.targeted_excerpts),
                    "semantic_diff_excerpts_selected": sum(
                        item.source_kind == "diff"
                        for item in semantic_case.packet.targeted_excerpts
                    ),
                    "semantic_excerpt_bytes_selected": sum(
                        item.content_bytes
                        for item in semantic_case.items
                        if item.section == "excerpt"
                    ),
                    # The owner-approved limits and the effective limits the case was built with,
                    # so a reader can tell whether consent or ceiling planning bound the excerpts
                    # (issue #907 Phase 1b). Neither is proof of delivery.
                    "semantic_excerpt_count_approved": review_selection.max_excerpts,
                    "semantic_excerpt_byte_approved": review_selection.max_total_excerpt_bytes,
                    "semantic_excerpt_count_limit": planned_selection.max_excerpts,
                    # A third cause: excerpts the approved selection lost so the case fits its
                    # aggregate item bound, before any ceiling planning (not consent).
                    "semantic_excerpt_count_cut_for_case_bound": (
                        approved_case.excerpts_cut_for_case_bound
                    ),
                    "semantic_excerpt_byte_limit": planned_selection.max_total_excerpt_bytes,
                    "semantic_excerpt_ceiling_rounds": ceiling_rounds,
                    "semantic_check_change_parts_selected": sum(
                        item.excerpt_item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
                        for item in semantic_case.packet.targeted_excerpts
                    ),
                    # Edit captures the frozen case holds, before any resolver fence: zero
                    # here with native edits in the session means none reached the ledger.
                    "semantic_edit_evidence_in_case": edit_capture_evidence_count(
                        frozen.case.projection
                    ),
                },
            )
            if captured_local_fence_required and captured_content_scope is not None:
                # A resolver may authenticate a group that the active excerpt selection then
                # omits. Keep the final disclosure fence only when retained bytes actually became
                # a case item; structural review can continue with an honest omission gap.
                captured_refs = frozenset(
                    ref for ref, _phase in captured_content_scope.phase_bindings
                )
                captured_local_fence_required = any(
                    item.section == "excerpt" and item.source_ref in captured_refs
                    for item in semantic_case.items
                )
            # The builder folds the gap into the packet coverage the reviewer sees; the check
            # result is a separate coverage fold, so carry the fact rather than re-deriving it.
            reference_scope_reduced = semantic_case.omitted_reference_count > 0
            # What the reviewer is shown bounds what its per-finding rulings may speak for, and
            # prior-finding rows envelope bounding removed are disclosed like any other cut.
            packet_view = semantic_case_packet_view(semantic_case)
            packet_prior_refs = packet_view.prior_finding_refs
            packet_settled_refs = packet_view.settled_finding_refs
            packet_citable_refs = packet_view.citable_refs
            # Issue #1047: a follow-up round is sent only when this case composes a requested part
            # no sent packet carried (``follow_up_new_parts`` below). What the round then showed
            # is read from the sent packet (``sent_excerpt_content_refs``, ``sent_excerpt_parts``).
            # Issue #907: which paths each captured edit records, compared in process only so a
            # repeated request for a captured edit can converge on a fresh diff of that path.
            packet_edit_paths = captured_edit_paths(
                frozen.case, captured_content, captured_content_scope
            )
            # tb4n5: what a current-diff follow-up could serve from the frozen change, per edit,
            # only where this recipe carries the change and the channel releases repository
            # excerpts. In process only.
            packet_section_parts = _follow_up_section_parts(
                semantic_case, check_change.change, packet_edit_paths, workspace_root, withheld
            )
            # tb4n2 A11: files Git found binary in the check-time change, for classifying a
            # suffix-less binary a reviewer names as Yoetz's limit. In process only.
            packet_binary_paths = check_change_binary_paths(
                None if check_change.change is None else check_change.change.capture
            )
            # ADR-045: the files the same change lists as text, so a suffix never overrules Git.
            packet_text_paths = check_change_text_paths(
                None if check_change.change is None else check_change.change.capture
            )
            trimmed_prior = set(_packet_view_gaps(packet_view))
            # The packet's coverage also carries task-level ledger gaps (plan drift, completion
            # scope, unreadable events). The reviewer still sees them in the packet and the check
            # reports them from the ledger; only case-content codes belong to the evaluation, which
            # rejects any other code and would turn a successful review into a coordinator failure.
            content_gaps = tuple(
                sorted(
                    trimmed_prior
                    | (set(semantic_case.packet.coverage.known_gaps) & SEMANTIC_EVALUATION_GAPS)
                    | set(test_edit_gaps)
                )
            )
            over_item_limit = (
                SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP
                in semantic_case.packet.coverage.known_gaps
            )
            if check_change.change is not None and runtime is not None:
                # Which changed files this packet carried, as keyed commitments: AI-powered
                # finding resolution compares them across checks (ADR-031). They are counted from
                # the bounded provider envelope, after minimization and the channel's withheld
                # categories, never from the case before them. A record that cannot be computed
                # says it is incomplete, which never tolerates a check-time limit.
                try:
                    check_change_files = await check_change_shown_files(
                        runtime,
                        check_change.change,
                        # Bytes, not parts: the planned selection may split the change into
                        # smaller parts, or cut its first part to the room left (issue #983).
                        check_time_change_bytes_carried(
                            semantic_case, withheld_categories=withheld
                        ),
                        # tb4n5: current-file sections a follow-up served are shown files too.
                        check_time_change_sections_carried(
                            semantic_case, withheld_categories=withheld
                        ),
                    )
                except Exception as exc:
                    record_unexpected_exception_without_raising(
                        exc,
                        component="semantic_composition",
                        operation="check_change_shown_files_failed",
                        request_id=frozen.lease.operation_id,
                    )
                    check_change_files = CheckChangeShownFiles((), (), complete=False)
            follow_up_base: tuple[str, int] | None = None
            if follow_up is not None:
                # Issue #1047: a round is sent only when its packet carries a requested excerpt
                # part no earlier packet of this check carried (tb4n5: per part, so a later part
                # of a partly shown source counts and a repeated one never does).
                # Counted over what admission keeps: the bounded envelope's catalog and what the
                # channel releases to either destination, so a round whose new parts admission
                # would drop is never sent.
                if not _admitted_follow_up_parts(semantic_case, follow_up, withheld):
                    return None
                if runtime is not None and job is not None:
                    assert recovered_case_digest is not None
                    follow_up_base = (recovered_case_digest, follow_up.round)
                    # The round owns its job, keyed by its own case digest; it keeps the base
                    # job's endpoint, retries and budget profile and gets its own deadline.
                    job = await runtime.ledger.load_semantic_job(
                        frozen.lease.writer_id,
                        frozen.lease.operation_id,
                        case_digest=semantic_case.case_digest,
                    )
                    execution = None
                    if job is not None:
                        (
                            execution,
                            _,
                            round_case_digest,
                            _,
                            round_base_digest,
                        ) = await _read_semantic_execution(runtime, job.case_object_ref)
                        if (
                            execution is None
                            or round_case_digest != semantic_case.case_digest
                            or round_base_digest != recovered_case_digest
                        ):
                            raise ValueError("semantic_follow_up_job_invalid")
                recovered_case_digest = None
            if (
                recovered_case_digest is not None
                and semantic_case.case_digest != recovered_case_digest
            ):
                raise ValueError("semantic_execution_case_changed")
            if execution is None:
                now = clock.now_utc()
                execution = _SemanticExecution(
                    provider,
                    fallback_binding,
                    fallback_plan,
                    operation_max_retries,
                    now + timedelta(seconds=total_timeout),
                    now
                    + timedelta(
                        seconds=total_timeout
                        + (fallback_timeout if fallback_plan is not None else 0.0)
                    ),
                    fallback_timeout,
                    select_semantic_budget_profile(
                        frozen.case.projection, final_review=final_review
                    ),
                )

            # UTC expiry is durable; monotonic time is reconstructed only from its remainder.
            # No replay, restart, or disclosure wait grants a fresh timeout budget.
            def remaining_deadline(expires_at: datetime) -> Deadline:
                remaining = max(0.0, (expires_at - clock.now_utc()).total_seconds())
                return Deadline(expires_at, clock.monotonic_seconds() + remaining)

            deadline = remaining_deadline(execution.expires_at)
            primary_deadline = remaining_deadline(execution.primary_expires_at)
            # Without a task runtime there is no durable ledger/object store: perform one
            # physical attempt only (tests and pre-dispatch probes). Production check always
            # supplies the runtime so the durable multi-attempt path below is authoritative.
            if runtime is None:
                candidate = semantic_case_to_candidate_context(
                    semantic_case,
                    request_id=frozen.lease.operation_id,
                    scope=scope,
                    provider_binding=provider,
                )
                with semantic_budget_profile_scope(execution.budget_profile):
                    result = await privacy.evaluate_semantic(candidate, primary_deadline)
                if attention is not None:
                    attention.record(provider, result)
                # The mapper knows only the egress outcome; the truncation happened while
                # composing the case, so it must be restated here or the probe path presents
                # a shortened case as complete.
                mapped = _map_egress_to_final(result, ids, projection=frozen.case.projection)
                return replace(
                    mapped,
                    case_content_over_item_limit=over_item_limit,
                    case_reference_scope_reduced=reference_scope_reduced,
                    case_content_gaps=tuple(
                        sorted(set(content_gaps) | set(mapped.case_content_gaps), key=str.encode)
                    ),
                    unsuppliable_missing_kinds=unsuppliable,
                    case_prior_finding_refs=packet_prior_refs,
                    case_settled_finding_refs=packet_settled_refs,
                    case_citable_refs=packet_citable_refs,
                    case_captured_edit_paths=packet_edit_paths,
                    case_binary_paths=packet_binary_paths,
                    case_text_paths=packet_text_paths,
                    case_workspace_root=workspace_root,
                    check_change_files=check_change_files,
                    review_input_manifest=input_manifest,
                    case_excerpt_refs=sent_excerpt_content_refs(
                        semantic_case, mapped.provider_input_manifest
                    ),
                    case_excerpt_parts=sent_excerpt_parts(
                        semantic_case, mapped.provider_input_manifest
                    ),
                    case_current_section_parts=packet_section_parts,
                    case_privacy_withheld_refs=withheld_excerpt_content_refs(
                        semantic_case, mapped.case_privacy_withheld_refs
                    ),
                )

            # Build the packet before anything durable exists. A packet that cannot be built is a
            # property of the case, not a transient fault, so it must not consume a job or an
            # attempt: claiming first is what let one local build failure strand a check
            # permanently, since claim resumes the same attempt on every replay.
            try:
                semantic_case_to_candidate_context(
                    semantic_case,
                    request_id=frozen.lease.operation_id,
                    scope=scope,
                    provider_binding=provider,
                )
            except SemanticCaseTooLarge:
                record_bounded_event_without_raising(
                    component="semantic_composition",
                    operation="semantic_not_dispatched_case_envelope_unbounded",
                    reason=SemanticReason.CASE_CAPACITY_EXCEEDED.value,
                    request_id=frozen.lease.operation_id,
                )
                return FinalSemanticEvaluation(
                    SemanticStatus.FAILED,
                    SemanticReason.CASE_CAPACITY_EXCEEDED,
                    operation_lease=current_lease[0],
                    withheld_review_categories=withheld,
                    case_content_over_item_limit=over_item_limit,
                    case_reference_scope_reduced=reference_scope_reduced,
                    case_content_gaps=content_gaps,
                    unsuppliable_missing_kinds=unsuppliable,
                    review_input_manifest=input_manifest,
                )

            # One durable AI-powered review job per check: create/recover after freeze, before dispatch.
            if job is None:
                case_ref = await _publish_semantic_case_object(
                    runtime,
                    case_digest=semantic_case.case_digest,
                    case_id=semantic_case.case_id,
                    dependency_digest=semantic_case.dependency_digest,
                    clock=clock,
                    execution=execution,
                    check_change=check_change.binding_json() if check_change.offered else None,
                    follow_up=follow_up_base,
                )
                job = await runtime.ledger.enqueue_semantic_job(
                    frozen.lease,
                    semantic_case.case_digest,
                    case_ref,
                )
            # Structural progress starts at the frozen execution deadline; a recovered job keeps
            # its original row, so replay never restarts its elapsed time (issue #571 A2).
            await _begin_semantic_progress(runtime, job, execution.expires_at, clock)

            def _dispatch_for(
                binding: ProviderBinding,
            ) -> Callable[[object, Deadline], Awaitable[FinalSemanticEvaluation]]:
                async def _captured_content_fence_current() -> bool:
                    if not captured_local_fence_required:
                        return True
                    if (
                        captured_local_fence_generation is None
                        or captured_observation_workspace is None
                        or local_observation is None
                    ):
                        return False
                    if (
                        _observation_workspace_for_runtime(runtime)
                        != captured_observation_workspace
                    ):
                        return False
                    checker = getattr(
                        local_observation,
                        "content_capture_authority_is_current",
                        None,
                    )
                    if not callable(checker):
                        return False
                    try:
                        return (
                            checker(
                                captured_observation_workspace,
                                captured_local_fence_generation,
                                captured_local_fence_profiles,
                            )
                            is True
                        )
                    except Exception:
                        return False

                async def _evaluate_with_fence(
                    candidate: CandidateContext,
                    attempt_deadline: Deadline,
                ) -> object:
                    # Keep a runtime compatibility seam for small composition fakes used by
                    # non-dispatch tests while retaining the concrete coordinator's final gate.
                    if type(privacy) is PrivacyCoordinator:
                        return await privacy.evaluate_semantic(
                            candidate,
                            attempt_deadline,
                            dispatch_guard=_captured_content_fence_current,
                        )
                    # Small composition fakes used by non-dispatch tests predate
                    # the optional final-boundary guard; the concrete production
                    # coordinator above owns that boundary.
                    return await privacy.evaluate_semantic(candidate, attempt_deadline)

                async def _resume_with_fence(
                    request_id: str,
                    case_digest: str,
                    attempt_deadline: Deadline,
                ) -> object:
                    if type(privacy) is PrivacyCoordinator:
                        return await privacy.resume(
                            request_id,
                            case_digest,
                            attempt_deadline,
                            dispatch_guard=_captured_content_fence_current,
                        )
                    return await privacy.resume(request_id, case_digest, attempt_deadline)

                async def _dispatch(
                    handle: object, attempt_deadline: Deadline
                ) -> FinalSemanticEvaluation:
                    from yoetz.ports.ledger import SemanticAttemptHandle as _Handle

                    assert type(handle) is _Handle
                    diagnostic_token = semantic_check_request.set(frozen.lease.operation_id)
                    progress_token = semantic_progress_sink.set(
                        _attempt_progress_sink(runtime, handle, clock)
                    )
                    stage = "privacy_admission"
                    # Every physical attempt, including resume and recovery, dispatches under
                    # the profile frozen with this job; configuration cannot re-select it.
                    budget_token = enter_semantic_budget_profile(execution.budget_profile)

                    async def _mapped(result: object) -> FinalSemanticEvaluation:
                        if attention is not None:
                            # Standing advice learns what only a real attempt can prove: an
                            # expired sign-in, rejected credential, or exhausted plan (#819).
                            attention.record(binding, result)
                        final = _map_egress_to_final(
                            result,
                            ids,
                            attempt_id=handle.attempt_id,
                            operation_request_id=frozen.lease.operation_id,
                            projection=frozen.case.projection,
                        )
                        if final.status in {SemanticStatus.SUCCEEDED, SemanticStatus.INVALID}:
                            # A provider response came back and is now validated and recorded.
                            await report_semantic_progress(
                                SemanticProgressPhase.RESPONSE_VALIDATION
                            )
                        return final

                    try:
                        await report_semantic_progress(SemanticProgressPhase.QUEUED)
                        # The local observation store is the authority for retained
                        # content. Its generation must still be current after all
                        # object resolution and before candidate bytes can enter the
                        # privacy coordinator's evaluate/resume path.
                        if not await _captured_content_fence_current():
                            return FinalSemanticEvaluation(
                                SemanticStatus.BLOCKED_BY_POLICY,
                                SemanticReason.SCOPE_NOT_AUTHORIZED,
                            )
                        # A newly claimed attempt gets a fresh request identity. A reclaimed started
                        # attempt deliberately keeps its original identity so the privacy audit can
                        # prove whether it was pre-admission or already consumed before replay.
                        candidate = semantic_case_to_candidate_context(
                            semantic_case,
                            request_id=handle.provider_request_id,
                            scope=scope,
                            provider_binding=binding,
                        )
                        wait = await runtime.ledger.load_disclosure_wait(
                            handle.writer_id, handle.operation_id
                        )
                        if not await _captured_content_fence_current():
                            return FinalSemanticEvaluation(
                                SemanticStatus.BLOCKED_BY_POLICY,
                                SemanticReason.SCOPE_NOT_AUTHORIZED,
                            )
                        stage = "privacy_dispatch_entered"
                        if type(privacy) is PrivacyCoordinator:
                            recovered = await privacy.recover_started_attempt(
                                handle.provider_request_id,
                                semantic_case.case_digest,
                                attempt_deadline,
                                dispatch_guard=_captured_content_fence_current,
                            )
                            if recovered is not None:
                                stage = "response_mapping"
                                return await _mapped(recovered)
                        if (
                            wait is not None
                            and wait.job_id == handle.job_id
                            and wait.attempt_id == handle.attempt_id
                            and wait.state == "awaiting"
                        ):
                            # Exact replay after a trusted local decision resumes the
                            # already-prepared proposal. Starting the AI-powered review pipeline again would
                            # mint a replacement proposal and could never observe the decision
                            # bound to this attempt.
                            result = await _resume_with_fence(
                                handle.provider_request_id,
                                semantic_case.case_digest,
                                attempt_deadline,
                            )
                        else:
                            result = await _evaluate_with_fence(candidate, attempt_deadline)
                        stage = "response_mapping"
                        return await _mapped(result)
                    except BaseException as exc:
                        record_unexpected_exception_without_raising(
                            exc,
                            component="semantic_composition",
                            operation=f"semantic_attempt_{stage}_failed",
                            request_id=frozen.lease.operation_id,
                        )
                        raise
                    finally:
                        exit_semantic_budget_profile(budget_token)
                        semantic_progress_sink.reset(progress_token)
                        semantic_check_request.reset(diagnostic_token)

                return _dispatch

            def _with_fallback_origin(
                provenance: SemanticProvenance | None, accounting: SemanticAttemptAccounting
            ) -> SemanticProvenance | None:
                """Name the primary on provenance the fallback produced (#582)."""

                if provenance is None or fallback_plan is None:
                    return provenance
                primary_slice = accounting.endpoint("primary")
                fallback_slice = accounting.endpoint("fallback")
                if (
                    primary_slice is None
                    or fallback_slice is None
                    or fallback_slice.attempted_count == 0
                    or provenance.provider != fallback_plan.fallback.provider_id
                    or provenance.endpoint_profile_id != fallback_plan.fallback.endpoint_profile_id
                    or provenance.model != fallback_plan.fallback.model_id
                ):
                    return provenance
                reason_token = (
                    primary_slice.predispatch_reason
                    if primary_slice.predispatch_reason is not None
                    else primary_slice.last_terminal_reason
                )
                if reason_token is None:
                    return provenance
                return replace(
                    provenance,
                    fallback_from=SemanticFallbackOrigin(
                        provider=fallback_plan.primary.provider_id,
                        endpoint_profile_id=fallback_plan.primary.endpoint_profile_id,
                        endpoint_profile_version=fallback_plan.primary.endpoint_profile_version,
                        model=fallback_plan.primary.model_id,
                        attempted_count=primary_slice.attempted_count,
                        reason=SemanticReason(reason_token),
                    ),
                )

            async def _publish_success(handle: object, evaluation: object) -> ObjectRef:
                from yoetz.ports.ledger import SemanticAttemptHandle as _Handle

                assert type(handle) is _Handle
                assert type(evaluation) is FinalSemanticEvaluation
                return await _publish_semantic_response_object(
                    runtime,
                    attempt_id=handle.attempt_id,
                    evaluation=evaluation,
                    clock=clock,
                )

            # ``current_lease`` / ``_on_lease_renewed`` are bound at the top of _evaluate so the
            # catch-all can return the newest token too, not only the normal returns here.
            from yoetz.ports.ledger import SemanticJobRecord as _JobRecord

            async def _recover_selected(job_row: object) -> FinalSemanticEvaluation | None:
                assert type(job_row) is _JobRecord
                return await _recover_selected_evaluation(runtime, job_row)

            def _build_final(
                status: SemanticStatus,
                reason: SemanticReason,
                evaluation: object | None,
                accounting: SemanticAttemptAccounting,
            ) -> FinalSemanticEvaluation:
                judgment = None
                provenance = None
                continuation = None
                disclosed: frozenset[str] | None = None
                withheld_refs: frozenset[str] | None = None
                privacy_refs: frozenset[str] = frozenset()
                semantic_withheld_item_ids: tuple[str, ...] = ()
                semantic_redacted_values: tuple[SemanticRedactedValue, ...] = ()
                provider_manifest = None
                provider_manifest_failure = None
                provider_input_text_by_ref = None
                evaluation_content_gaps: tuple[str, ...] = ()
                if type(evaluation) is FinalSemanticEvaluation:
                    semantic_withheld_item_ids = evaluation.semantic_withheld_item_ids
                    semantic_redacted_values = evaluation.semantic_redacted_values
                    evaluation_content_gaps = evaluation.case_content_gaps
                    if status is SemanticStatus.SUCCEEDED:
                        judgment = evaluation.judgment
                        provenance = evaluation.provenance
                        # What the exact sent packet carried, from the selected attempt (#904).
                        disclosed = evaluation.case_included_refs
                        withheld_refs = evaluation.case_withheld_refs
                        privacy_refs = evaluation.case_privacy_withheld_refs
                        provider_manifest = evaluation.provider_input_manifest
                        provider_manifest_failure = evaluation.provider_input_manifest_failure
                        provider_input_text_by_ref = evaluation.provider_input_text_by_ref
                    elif (
                        status is evaluation.status
                        and reason is evaluation.reason
                        and evaluation.provenance is not None
                    ):
                        provenance = evaluation.provenance
                    if status is SemanticStatus.AWAITING_HUMAN:
                        continuation = evaluation.continuation
                provenance = _with_fallback_origin(provenance, accounting)
                if provenance is None and status is not SemanticStatus.SUCCEEDED:
                    status, reason = _without_provider_provenance(status, reason)
                combined_content_gaps = tuple(
                    sorted(set(content_gaps) | set(evaluation_content_gaps), key=str.encode)
                )
                # Terminal recovery of a succeeded job without a recoverable response object
                # must not invent a judgment; surface an honest coordinator failure instead.
                if status is SemanticStatus.SUCCEEDED and (judgment is None or provenance is None):
                    return FinalSemanticEvaluation(
                        SemanticStatus.FAILED,
                        SemanticReason.COORDINATOR_FAILURE,
                        attempt_accounting=accounting,
                        operation_lease=current_lease[0],
                        withheld_review_categories=withheld,
                        case_content_over_item_limit=over_item_limit,
                        case_reference_scope_reduced=reference_scope_reduced,
                        case_content_gaps=combined_content_gaps,
                        unsuppliable_missing_kinds=unsuppliable,
                        semantic_withheld_item_ids=semantic_withheld_item_ids,
                        semantic_redacted_values=semantic_redacted_values,
                        review_input_manifest=input_manifest,
                        provider_input_manifest=provider_manifest,
                        provider_input_manifest_failure=provider_manifest_failure,
                        provider_input_text_by_ref=provider_input_text_by_ref,
                    )
                return FinalSemanticEvaluation(
                    status,
                    reason,
                    judgment=judgment,
                    provenance=provenance,
                    attempt_accounting=accounting,
                    operation_lease=current_lease[0],
                    withheld_review_categories=withheld,
                    credential_heuristic_disabled=credential_heuristic_disabled,
                    case_content_over_item_limit=over_item_limit,
                    case_reference_scope_reduced=reference_scope_reduced,
                    case_included_refs=disclosed,
                    case_withheld_refs=withheld_refs,
                    # A withheld captured group's parts with its lead; recovery expands the same
                    # recorded refs over the same case.
                    case_privacy_withheld_refs=withheld_excerpt_content_refs(
                        semantic_case, privacy_refs
                    ),
                    semantic_withheld_item_ids=semantic_withheld_item_ids,
                    semantic_redacted_values=semantic_redacted_values,
                    case_content_gaps=combined_content_gaps,
                    unsuppliable_missing_kinds=unsuppliable,
                    case_prior_finding_refs=packet_prior_refs,
                    case_settled_finding_refs=packet_settled_refs,
                    case_citable_refs=packet_citable_refs,
                    case_captured_edit_paths=packet_edit_paths,
                    case_binary_paths=packet_binary_paths,
                    case_text_paths=packet_text_paths,
                    case_workspace_root=workspace_root,
                    check_change_files=check_change_files,
                    continuation=continuation,
                    review_input_manifest=input_manifest,
                    # Recovery reads the same provider-bound manifest from the durable response.
                    case_excerpt_refs=sent_excerpt_content_refs(semantic_case, provider_manifest),
                    case_excerpt_parts=sent_excerpt_parts(semantic_case, provider_manifest),
                    case_current_section_parts=packet_section_parts,
                    provider_input_manifest=provider_manifest,
                    provider_input_manifest_failure=provider_manifest_failure,
                    provider_input_text_by_ref=provider_input_text_by_ref,
                )

            return cast(
                FinalSemanticEvaluation,
                await run_durable_semantic_attempts(
                    ledger=runtime.ledger,
                    lease=frozen.lease,
                    job=job,
                    deadline=deadline,
                    primary_deadline=primary_deadline,
                    fallback_timeout_seconds=execution.fallback_timeout_seconds,
                    now_utc=clock.now_utc,
                    max_retries=operation_max_retries,
                    now_monotonic=clock.monotonic_seconds,
                    dispatch=_dispatch_for(provider),
                    publish_success_response=_publish_success,
                    build_final=_build_final,
                    recover_selected=_recover_selected,
                    recover_response=lambda ref: _recover_response_evaluation(runtime, ref),
                    on_lease_renewed=_on_lease_renewed,
                    fallback=fallback_plan,
                    dispatch_fallback=(
                        None if fallback_binding is None else _dispatch_for(fallback_binding)
                    ),
                ),
            )
        except PublicOperationError:
            # Retryable durable-state conflicts remain public pending state; collapsing one into
            # coordinator_failure would tell the caller the opposite of what the ledger knows.
            raise
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="semantic_composition",
                operation="semantic_evaluation_failed",
                request_id=frozen.lease.operation_id,
            )
            try:
                return FinalSemanticEvaluation(
                    SemanticStatus.FAILED,
                    SemanticReason.COORDINATOR_FAILURE,
                    operation_lease=current_lease[0],
                    withheld_review_categories=withheld,
                    case_content_over_item_limit=over_item_limit,
                    case_reference_scope_reduced=reference_scope_reduced,
                    case_content_gaps=content_gaps,
                    unsuppliable_missing_kinds=unsuppliable,
                )
            except ValueError as detail_exc:
                # The failure record itself must never lose the renewed lease: raising here sent
                # the check to the outer fence with a stale lease, and it stayed OPERATION_PENDING
                # forever. Keep only the fields that cannot fail validation.
                record_unexpected_exception_without_raising(
                    detail_exc,
                    component="semantic_composition",
                    operation="semantic_failure_detail_dropped",
                    request_id=frozen.lease.operation_id,
                )
                # Keep the coverage gaps the evaluation can still carry, so the failed check does
                # not under-report what its case lacked.
                admissible_gaps = tuple(
                    sorted(set(content_gaps) & SEMANTIC_EVALUATION_GAPS, key=str.encode)
                )
                try:
                    return FinalSemanticEvaluation(
                        SemanticStatus.FAILED,
                        SemanticReason.COORDINATOR_FAILURE,
                        operation_lease=current_lease[0],
                        case_content_gaps=admissible_gaps,
                    )
                except ValueError:
                    return FinalSemanticEvaluation(
                        SemanticStatus.FAILED,
                        SemanticReason.COORDINATOR_FAILURE,
                        operation_lease=current_lease[0],
                    )

    return _evaluate


def _profile(config: YoetzConfig) -> RuntimeProfile:
    return RuntimeProfile(config.profile)


def _policy_packs(manifest: Mapping[str, CanonicalJsonValue]) -> tuple[str, ...]:
    values = manifest["policy_versions"]
    if type(values) is not list or any(type(item) is not str for item in values):
        raise ValueError("version_manifest_invalid")
    # The version manifest also advertises the coordination policy used by the lineage
    # authority.  Start/receipt version slices carry the two user-facing verification packs;
    # exposing the coordination authority here violates their closed wire contract.
    packs = tuple(cast(list[str], values))
    user_facing = {
        current_policy_pack(RESEARCH_EVIDENCE_POLICY_ID),
        current_policy_pack(WORK_INTEGRITY_POLICY_ID),
    }
    return tuple(item for item in packs if item in user_facing)


def _record_external_runtime_state(state: Callable[[], str | None] | None, request_id: str) -> None:
    """Name the exact structural refusal behind an unresolved Codex subscription endpoint.

    The public outcome stays ``credential_unavailable``; this request-joined companion record
    carries the closed structural token (a replaced executable, an outdated capability identity,
    a changed isolated config, ...) so the diagnosis never depends on a login probe (#855).
    """

    if state is None:
        return
    try:
        token = state()
    except Exception:
        return
    if token is None or token == "ready":
        return
    record_bounded_event_without_raising(
        component="semantic_composition",
        operation="semantic_external_runtime_unready",
        reason=token,
        request_id=request_id,
    )


def subscription_runtime_structurally_ready(
    runtime: object, *, now: datetime | None = None
) -> bool:
    """READY fact for Codex OAuth: unexpired evidence, exact binding, digest, and home.

    Login and model availability stay inside the evaluate() child. A READY snapshot
    must not spawn a preflight app-server process group.
    """

    if type(runtime) is not ExternalRuntimeProfileConfig:
        return False
    try:
        profile = CodexAppServerProfile.from_config(runtime)
        profile.verify_capability_evidence(datetime.now(UTC) if now is None else now)
        profile.verify_local_binding()
    except (OSError, TypeError, ValueError):  # fmt: skip
        return False
    return True


type _StatFingerprint = tuple[int, int, int, int, int, int, int]


def _stat_fingerprint(path: Path) -> _StatFingerprint:
    facts = os.stat(path)
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
        facts.st_mode,
        facts.st_uid,
    )


class SubscriptionReadinessMemo:
    """Structural READY memo for the Codex subscription binding (#881).

    ``subscription_runtime_structurally_ready`` hashes the retained executable and code-mode host
    (hundreds of MiB). Credential presence is asked on every observation advice cycle, so this
    memo re-runs it, off the event loop, only when the exact binding or a stat fingerprint of the
    executable, code-mode host, dedicated home, or isolated config changed. Evidence expiry is
    checked against the clock on every call. The launch fence is not cached: every
    ``evaluate()`` child launch still hashes both files through ``verify_local_binding``.
    """

    def __init__(self) -> None:
        self._key: tuple[object, ...] | None = None
        self._ready = False

    @staticmethod
    def _fingerprint(runtime: ExternalRuntimeProfileConfig) -> tuple[object, ...] | None:
        executable = Path(runtime.executable_path)
        home = Path(runtime.codex_home)
        try:
            files = tuple(
                _stat_fingerprint(path)
                for path in (
                    executable,
                    codex_code_mode_host_path(executable),
                    home,
                    home / "config.toml",
                )
            )
        except OSError:
            return None
        return (runtime.model_dump_json(), sys.platform, platform.machine(), files)

    async def ready(self, runtime: object, *, now: datetime) -> bool:
        if type(runtime) is not ExternalRuntimeProfileConfig:
            return False
        try:
            CodexAppServerProfile.from_config(runtime).verify_capability_evidence(now)
        except (TypeError, ValueError):  # fmt: skip
            return False
        before = self._fingerprint(runtime)
        if before is not None and before == self._key:
            return self._ready
        ready = await asyncio.to_thread(subscription_runtime_structurally_ready, runtime, now=now)
        # Remember only a result whose inputs held still while it was hashed.
        if before is not None and self._fingerprint(runtime) == before:
            self._key, self._ready = before, ready
        else:
            self._key = None
        return ready


class _RoutedCoordinationDetailStore:
    """Write detector details through a short-lived, generation-bound task lease."""

    def __init__(
        self,
        resolver: Callable[[str, int], Awaitable[ProjectObjectStoreLease | None]],
        *,
        clock: ClockPort,
    ) -> None:
        self._resolver = resolver
        self._clock = clock

    async def put_details(
        self,
        detection_id: str,
        details: JsonObject,
        *,
        owner_task_id: str,
        route_generation: int,
    ) -> ProjectTextRef:
        lease = await self._resolver(owner_task_id, route_generation)
        if not isinstance(lease, ProjectObjectStoreLease):
            raise CoordinationError(CoordinationErrorCode.INVALID)
        try:
            return await EncryptedCoordinationDetailStore(
                lease.store,
                clock=self._clock,
            ).put_details(
                detection_id,
                details,
                owner_task_id=owner_task_id,
                route_generation=route_generation,
            )
        finally:
            released = lease.release()
            if inspect.isawaitable(released):
                await released

    async def read_details(self, reference: ProjectTextRef) -> JsonObject:
        lease = await self._resolver(reference.owner_task_id, reference.route_generation)
        if not isinstance(lease, ProjectObjectStoreLease):
            raise CoordinationError(CoordinationErrorCode.INVALID)
        try:
            return await EncryptedCoordinationDetailStore(
                lease.store,
                clock=self._clock,
            ).read_details(reference)
        finally:
            released = lease.release()
            if inspect.isawaitable(released):
                await released


async def provide_service_ready_context(
    service_generation: int,
    vault_generation: int,
    *,
    lifecycle: _Lifecycle,
    vault: _Vault,
    config: YoetzConfig,
    paths: _Paths,
    clock: ClockPort,
    secret_memory: object,
    diagnostics: DiagnosticsPort | None = None,
    observation_gate: asyncio.Lock | None = None,
    startup_bundle_upgrade: _StartupBundleUpgrade | None = None,
) -> ServiceReadyContext:
    """Compose one generation-bound ready application context."""

    if not vault.ready or vault.generation != vault_generation:
        raise ControlError("vault_locked", retryable=True)
    ensure_owner_only_dir(paths.bundle)
    verify_private_local_bundle(paths.bundle)
    ids = IdPort()
    lookup = vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
    lineage_key = vault.installation_mac_handle(MacKeyPurpose.LINEAGE_ATTACH)
    installation_id = cast(str, getattr(vault, "_installation_id"))
    catalog = await open_ready_catalog(
        _catalog_path(paths),
        installation_id=installation_id,
        service_generation=service_generation,
        lookup=lookup,
        clock=clock,
        ids=ids,
    )
    # The storage-owned startup phase is deliberately after catalog migration and before any
    # lineage/runtime clients are composed.  It may inspect and upgrade existing task bundles,
    # but ordinary lazy runtime opening remains fail-closed for a stale schema.  A failed phase
    # closes the catalog immediately so a retry cannot race a half-composed generation.
    if startup_bundle_upgrade is not None:
        try:
            await startup_bundle_upgrade(
                catalog=catalog,
                bundle_root=paths.bundle,
                installation_id=installation_id,
                service_generation=service_generation,
                vault_generation=vault_generation,
                clock=clock,
                ids=ids,
                diagnostics=diagnostics,
            )
        except BaseException:
            _close_db(cast(apsw.Connection | None, getattr(catalog, "_db", None)))
            raise
    # Lineage shares the catalog connection with start/status.  The adapter only validates the
    # numbered catalog migration; all lineage tables are installed by that migration before this
    # composition point.  The handle MAC is installation-owned and never falls back to a fixed
    # process constant.
    lineage_store = SqliteLineageStore(
        cast(apsw.Connection, getattr(catalog, "_db")),
        installation_id=installation_id,
        clock=clock,
        ids=ids,
        contact_lost_recovery_seconds=config.lineage.contact_lost_recovery_seconds,
    )
    host_lineage_registry = SqliteHostLineageRegistry(
        cast(apsw.Connection, getattr(catalog, "_db")),
        installation_id=installation_id,
        mac=lookup,
        clock=clock,
    )

    async def _shared_lineage_project(parent_task_id: str, child_task_id: str) -> str | None:
        """Resolve one active project shared by the two lineage source tasks.

        Cross-repository lineage has no implicit selector.  The resolver therefore requires one
        unambiguous current project before the generation-bound project admission is consulted.
        """

        try:
            parent_projects = set(await catalog.list_task_project_ids(parent_task_id))
            child_projects = set(await catalog.list_task_project_ids(child_task_id))
            candidates: list[str] = []
            for identifier in sorted(parent_projects & child_projects, key=str.encode):
                descriptor = await catalog.project_state(identifier)
                if descriptor is not None and getattr(descriptor, "dissolved_at", None) is None:
                    candidates.append(identifier)
            return candidates[0] if len(candidates) == 1 else None
        except Exception:
            return None

    async def _merge_host_annotation(values: Mapping[str, CanonicalJsonValue]) -> None:
        """Bind a service-validated cooperative start to its pending host observation."""

        parent_value = values.get("parent_task_id")
        child_value = values.get("child_task_id")
        if type(parent_value) is not str or type(child_value) is not str:
            return
        host_value = values.get("host")
        if host_value is not None and host_value not in {"claude", "codex", "cursor"}:
            return
        subagent_value = values.get("subagent_id")
        parent_tool_value = values.get("parent_tool_call_id")
        correlation_value = values.get("correlation_id")
        await host_lineage_registry.bind_host_lineage_identity(
            parent_value,
            child_value,
            host=(None if host_value is None else cast(HostLineageHost, host_value)),
            subagent_id=(subagent_value if type(subagent_value) is str else None),
            parent_tool_call_id=(parent_tool_value if type(parent_tool_value) is str else None),
            correlation_id=(correlation_value if type(correlation_value) is str else None),
            validate_only=values.get("validate_only") is True,
        )

    # The resolver is installed before ProjectApplication is composed because the lineage
    # coordinator is needed by START.  It is invoked only after READY has bound the facade below;
    # a missing or refused authority is a bounded denial, never an implicit same-repository grant.
    project_application: ProjectApplication | None = None

    async def _lineage_project_admission(
        parent_task_id: str, child_repository_commitment: str
    ) -> LineageProjectAdmission | None:
        if project_application is None:
            return None
        try:
            result = await project_application.admit_cross_repository_child(
                parent_task_id,
                child_repository_commitment,
            )
        except ProjectCommandError:
            return None
        return result if type(result) is LineageProjectAdmission else None

    # The in-process binding is populated by admitted observation envelopes.  Recovery can run
    # after a service restart before another envelope arrives, so bootstrap the exact host
    # commitment from the durable observation route for this task/session pair.  Every lookup is
    # fenced by the current catalog route and fails closed when the bundle route is unavailable.
    runtime_ref: BundleRuntimePort | None = None

    async def _current_host_session_commitment(task_id: str, session_id: str) -> str | None:
        current_runtime = runtime_ref
        leased: TaskRuntime | None = None
        try:
            route = await catalog.task_route(task_id)
            if (
                route is None
                or route.state is not TaskRouteState.ACTIVE
                or route.session_id != session_id
            ):
                return None
            binding = await catalog.session_binding(session_id)
            if binding is None or binding.task_id != task_id or binding.session_id != session_id:
                return None
            if current_runtime is None:
                return None
            leased = await current_runtime.route(
                RouteCommand(
                    session_id,
                    binding.writer_id,
                    RouteAccess.MAINTENANCE,
                    frozenset({RuntimeCapability.WRITE}),
                )
            )
            if (
                type(leased) is not TaskRuntime
                or leased.task_id != task_id
                or leased.session_id != session_id
                or leased.writer_id != binding.writer_id
            ):
                return None
            observation = leased.observation
            workspace_lookup = getattr(observation, "workspace_for_yoetz_session", None)
            route_lookup = getattr(observation, "observation_route_for_session", None)
            if not callable(workspace_lookup) or not callable(route_lookup):
                return None
            workspace = workspace_lookup(session_id)
            if type(workspace) is not str:
                return None
            observed_route = route_lookup(
                workspace=workspace,
                yoetz_session_id=session_id,
            )
            if type(observed_route) is not tuple:
                return None
            route_values = cast(tuple[object, ...], observed_route)
            if len(route_values) != 3:
                return None
            commitment, routed_task, active = route_values
            if type(commitment) is not str or routed_task != task_id or active is not True:
                return None
            validate_commitment(commitment)
            latest = await catalog.task_route(task_id)
            if (
                latest is None
                or latest.state is not TaskRouteState.ACTIVE
                or latest.task_id != task_id
                or latest.session_id != session_id
                or latest.route_generation != route.route_generation
                or latest.route_identity_digest != route.route_identity_digest
            ):
                return None
            return commitment
        except Exception:
            return None
        finally:
            if leased is not None and current_runtime is not None:
                try:
                    await current_runtime.release(leased)
                except Exception:
                    pass

    lineage = LineageCoordinator(
        store=lineage_store,
        clock=clock,
        ids=ids,
        config=LineageConfig(
            start_lease_seconds=config.lineage.start_lease_seconds,
            attach_handle_ttl_seconds=config.lineage.attach_handle_ttl_seconds,
            contact_lost_recovery_seconds=config.lineage.contact_lost_recovery_seconds,
            max_depth=config.lineage.max_depth,
            max_fanout=config.lineage.max_fanout,
        ),
        handle_mac=lambda value: lineage_key.mac(LINEAGE_ATTACH_MAC_DOMAIN, value.encode("ascii")),
        owner_generation=max(1, service_generation),
        host_annotation_merger=_merge_host_annotation,
        host_lineage_registry=host_lineage_registry,
        host_session_commitment_lookup=_current_host_session_commitment,
        project_admission_resolver=_lineage_project_admission,
    )
    manifest = _version_json()
    privacy, policy, gateway = await build_privacy_coordinator(
        catalog_db=cast(apsw.Connection, getattr(catalog, "_db")),
        installation_id=installation_id,
        service_generation=service_generation,
        vault_generation=vault_generation,
        vault=vault,
        clock=clock,
        ids=ids,
        config=config,
    )
    privacy_application = cast(PrivacyCoordinator, privacy).policy_application
    lineage_semantic_gate = (
        None
        if privacy_application is None
        else PrivacyLineageSourceGate(
            privacy_application.policy_store,
            installation_id,
            project_resolver=_shared_lineage_project,
        )
    )
    provider_factory_ids = cast(
        tuple[str, ...], tuple(getattr(gateway, "configured_provider_ids", lambda: ())())
    )
    connected_provider_ids = cast(
        tuple[str, ...], tuple(getattr(gateway, "connected_provider_ids", lambda: ())())
    )
    semantic_configured = config.verification.semantic != "disabled"
    provider_endpoint_bound = config.provider is not None or config.external_runtime is not None
    # Preserve the composition-time snapshot for readiness/status, but resolve the configured
    # binding again for every check so a later registry activation can take effect immediately.
    # With a declared pairing (#582) the primary keeps every existing name below and the
    # fallback gets its own, so a single-endpoint install reads exactly as before.
    primary_config = primary_external_endpoint(config)
    fallback_config = fallback_external_endpoint(config)

    def _binding_of(
        endpoint: ExternalRuntimeProfileConfig | ProviderProfileConfig | None,
    ) -> ProviderBinding | None:
        if endpoint is None:
            return None
        if type(endpoint) is ExternalRuntimeProfileConfig:
            return codex_binding_from_config(endpoint)
        return provider_binding_from_config(cast(ProviderProfileConfig, endpoint))

    candidate_binding = _binding_of(primary_config)
    fallback_candidate_binding = _binding_of(fallback_config)

    def external_runtime_state() -> str | None:
        # Local structure only: no Codex process, login probe, or credential read (#855).
        runtime = config.external_runtime
        if runtime is None:
            return None
        return diagnose_codex_binding(runtime, now=clock.now_utc()).state

    def binding_not_connected(_binding: ProviderBinding) -> bool:
        return False

    # One structural memo per bound endpoint of this generation; recomposition starts clean.
    subscription_readiness: dict[int, SubscriptionReadinessMemo] = {}

    async def _credential_present(
        endpoint: ExternalRuntimeProfileConfig | ProviderProfileConfig | None,
        binding: ProviderBinding | None,
    ) -> bool:
        if endpoint is None or binding is None:
            return False
        if type(endpoint) is ExternalRuntimeProfileConfig:
            memo = subscription_readiness.setdefault(id(endpoint), SubscriptionReadinessMemo())
            return await memo.ready(endpoint, now=clock.now_utc())
        credential_binding = provider_credential_profile_binding(
            binding.provider_id,
            binding.model_id,
            binding.endpoint_profile_id,
            binding.endpoint_profile_version,
        )
        return await vault.has_provider_credential(credential_binding)

    async def configured_provider_credential_present() -> bool:
        return await _credential_present(primary_config, candidate_binding)

    async def configured_fallback_credential_present() -> bool:
        return await _credential_present(fallback_config, fallback_candidate_binding)

    async def _resolve_binding(
        binding: ProviderBinding | None, credential_present: Callable[[], Awaitable[bool]]
    ) -> ProviderBinding | None:
        if binding is None:
            return None
        binding_connected = cast(
            Callable[[ProviderBinding], bool],
            getattr(gateway, "has_connected_provider_binding", binding_not_connected),
        )
        if binding_connected(binding) is not True:
            return None
        if not await credential_present():
            return None
        return binding

    async def resolve_provider_binding() -> ProviderBinding | None:
        return await _resolve_binding(candidate_binding, configured_provider_credential_present)

    async def resolve_fallback_binding() -> ProviderBinding | None:
        return await _resolve_binding(
            fallback_candidate_binding, configured_fallback_credential_present
        )

    # Repository authority is session-specific, so ready-time composition cannot activate a
    # provider binding or claim AI-powered review readiness. Exact configured-credential presence is a
    # separate structural vault fact: it neither decrypts the record nor grants dispatch authority.
    provider_credential_connected = await configured_provider_credential_present()
    fallback_credential_connected = await configured_fallback_credential_present()
    semantic_ready = False
    # Per-generation memory of the last user-repairable attempt outcome (#819). Recomposition
    # after setup, sign-in, or disconnect replaces it, so a repaired path starts clean.
    semantic_attention = SemanticAttentionTracker((candidate_binding, fallback_candidate_binding))

    async def semantic_review_facts() -> tuple[bool, bool] | None:
        """Current ``(review intended, structurally usable)`` machine facts, or ``None``.

        Standing provider advice and background advice admission (#923) both rest on these,
        read now rather than from the READY-time snapshot.
        """

        # Credential presence changes at runtime and the connected registry only fills lazily
        # on repository-scoped dispatch, so frozen values would advise connect_provider against
        # an installation that just dispatched successfully (#265). Structural usability claims
        # no repository authority; an unreadable fact (for example a vault locking race) yields
        # no fact rather than a false not-ready claim.
        try:
            if privacy_application is None:
                return None
            effective = await privacy_application.policy_store.effective_policy(
                AuthorizationScope(AuthorizationScopeKind.MACHINE, installation_id)
            )
            # Verification defaults alone do not express provider intent (#844).
            # Read the current machine ceiling, not the READY-time policy snapshot;
            # update-check egress alone must not enable provider repair advice.
            review_intended = (
                semantic_configured
                and provider_endpoint_bound
                and _admits_llm_inference(effective.policy)
            )
            # provider_factory_ids is provider-id grain while factories are
            # keyed by full binding; the id test is exact today because the
            # factory set is built from this same config.provider through the
            # same provider_binding_from_config, so an id match implies the
            # binding match. The credential probe below is full-binding grain.
            structurally_usable = (
                candidate_binding is not None
                and candidate_binding.provider_id in provider_factory_ids
                and await configured_provider_credential_present()
            )
        except Exception:
            return None
        return review_intended, structurally_usable

    async def observation_composition_fact() -> ObservationCompositionFact | None:
        facts = await semantic_review_facts()
        if facts is None:
            return None
        review_intended, structurally_usable = facts
        try:
            connected_now = cast(
                tuple[str, ...], tuple(getattr(gateway, "connected_provider_ids", lambda: ())())
            )
        except Exception:
            return None
        attention = semantic_attention.current(candidate_binding, fallback_candidate_binding)
        return ObservationCompositionFact(
            semantic_configured=review_intended,
            semantic_ready=structurally_usable,
            provider_factory_ids=provider_factory_ids,
            connected_provider_ids=connected_now,
            semantic_attention=None if attention is None else attention[0],
            semantic_attention_provider=None if attention is None else attention[1],
        )

    async def advice_semantic_provider_ready() -> bool:
        """Background advice may reach a provider only when one is usable now (#923).

        The same facts as standing provider advice: review wanted, an endpoint bound, the
        machine policy admitting LLM-inference egress, and the configured credential present.
        An unreadable fact admits nothing.
        """

        facts = await semantic_review_facts()
        return facts is not None and facts[0] and facts[1]

    capabilities = {
        RuntimeCapability.STRUCTURAL_READ,
        RuntimeCapability.PAYLOAD_READ,
        RuntimeCapability.WRITE,
    }
    # Expose SEMANTIC when the operator has not disabled it so check can report *why* it is
    # unusable (no endpoint vs no credential vs policy), instead of one opaque not_configured.
    if semantic_configured:
        capabilities.add(RuntimeCapability.SEMANTIC)
    runtime_context = ServiceRuntimeContext(
        service_instance_id=cast(str, getattr(lifecycle.instance, "instance_id")),
        service_generation=service_generation,
        vault_generation=vault_generation,
        catalog_generation=catalog.generation,
        capabilities=frozenset(capabilities),
        version_manifest=cast(Mapping[str, DomainJsonValue], manifest),
        shutdown_token=object(),
    )
    factories = build_runtime_adapter_factories(
        paths=paths,
        service_instance_id=runtime_context.service_instance_id,
        service_generation=service_generation,
        clock=clock,
        ids=ids,
        secret_memory=secret_memory,
        catalog_db=cast(apsw.Connection, getattr(catalog, "_db")),
    )
    runtime = await open_local_bundle_runtime(
        runtime_context,
        catalog,
        vault,
        factories,
        diagnostics or _NullDiagnostics(),
        manifest,
    )
    runtime_ref = runtime

    def generation_is_current(current_service: int, current_vault: int) -> bool:
        return (
            current_service == service_generation
            and current_vault == vault_generation
            and vault.ready
            and vault.generation == vault_generation
        )

    def disclosure_scope_for(
        binding: ControlProjectionBinding, source: Mapping[str, CanonicalJsonValue]
    ) -> AuthorizationScope:
        if binding.method in {
            ControlMethod.PRIVACY_GET_SETUP,
            ControlMethod.PRIVACY_GET_EFFECTIVE,
            ControlMethod.PRIVACY_PROPOSE_POLICY,
        }:
            if binding.repository_privacy_commitment is not None:
                return AuthorizationScope(
                    AuthorizationScopeKind.WORKSPACE,
                    installation_id,
                    binding.repository_privacy_commitment,
                )
            return AuthorizationScope(AuthorizationScopeKind.MACHINE, installation_id)
        task = source.get("task_id")
        if type(task) is str and binding.route_identity_digest is not None:
            workspace = lookup.mac(
                WORKSPACE_REF_DOMAIN,
                f"{binding.route_identity_digest}\x00{task}".encode("ascii"),
            )
            return AuthorizationScope(
                AuthorizationScopeKind.TASK,
                installation_id,
                workspace,
                task,
            )
        return AuthorizationScope(
            AuthorizationScopeKind.MACHINE,
            installation_id,
        )

    versions = _receipt_versions(manifest)
    # Name this process's store-lock ownership and route lock timeouts and long holds, with the
    # holder's role and phase, to the diagnostic ring. Hook replays on the spool worker keep their
    # own scoped attribution (#689).
    set_observation_store_lock_role("service")
    set_observation_store_lock_reporter(_record_observation_store_lock_event)
    local_observation = LocalObservationStore(_state=paths.state)
    # Publish the loaded config gate before AI-powered review composition can resolve
    # retained bytes. The owner-private store is also the authoritative consent
    # fence while task-bundle propagation is still catching up.
    local_observation.set_runtime_enabled(config.observation.enabled)
    # Planned-verification facts (#977) compare a requested command with observed runs through
    # the same installation-keyed commitment the hooks compute; without the key they are omitted.
    with contextlib.suppress(Exception):
        register_command_identity_key(local_observation.key_material())
    require_capture_bootstrap = getattr(
        local_observation, "set_capture_reservation_bootstrap_required", None
    )
    if callable(require_capture_bootstrap):
        require_capture_bootstrap(True)

    async def bootstrap_capture_reservations(
        workspace: str,
        current_runtime: TaskRuntime,
        current_store: TaskObservationPort,
    ) -> bool:
        return await _bootstrap_capture_reservations(
            workspace,
            current_runtime,
            current_store,
            catalog=catalog,
            runtime=runtime,
            local_observation=local_observation,
            clock=clock,
            generation_is_current=lambda: generation_is_current(
                service_generation, vault_generation
            ),
        )

    async def reconcile_observation_capture(runtime: TaskRuntime) -> None:
        # The CHECK barrier preflight: current local authority first, then (when
        # the capture lock is free) the structural row of each aged handoff, so
        # a ticket with no deliverable row cannot hold the freeze (#836).
        await observation_coordinator.reconcile_task_capture_handoffs(runtime)

    async def reconcile_capture_handoffs(
        workspace: str,
        task_ids: tuple[str, ...],
        visit: Callable[[TaskRuntime, TaskObservationPort], Awaitable[int]],
    ) -> bool:
        return await _reconcile_capture_handoffs(
            workspace,
            task_ids,
            visit,
            catalog=catalog,
            runtime=runtime,
            generation_is_current=lambda: generation_is_current(
                service_generation, vault_generation
            ),
        )

    # One read-only Git adapter serves both the task-start base and the check-time change.
    change_capture = GitChangeCaptureAdapter()
    if not semantic_configured:
        semantic_evaluator = _semantic_not_configured
    elif not provider_endpoint_bound:
        semantic_evaluator = _semantic_provider_unbound
    else:
        provider_cfg = primary_config
        semantic_evaluator = _privacy_gated_semantic_evaluator(
            cast(PrivacyCoordinator, privacy),
            clock,
            installation_id,
            resolve_provider_binding,
            catalog,
            ids,
            timeout_seconds=60 if provider_cfg is None else int(provider_cfg.timeout_seconds),
            max_retries=2 if provider_cfg is None else int(provider_cfg.max_retries),
            resolve_fallback=None if fallback_config is None else resolve_fallback_binding,
            fallback_timeout_seconds=(
                60 if fallback_config is None else int(fallback_config.timeout_seconds)
            ),
            fallback_max_retries=2 if fallback_config is None else int(fallback_config.max_retries),
            external_runtime_state=external_runtime_state,
            configured_primary=candidate_binding,
            lineage_source_gate=lineage_semantic_gate,
            local_observation=local_observation,
            attention=semantic_attention,
            change_capture=change_capture,
        )

    # attempt_id -> (physical request identity, provider identity) of the single in-flight
    # advisory dispatch. Cleared on every dispatch and consumed by the cancellation reconciler.
    advice_semantic_inflight: dict[str, tuple[str, str]] = {}
    service_started_at = clock.now_utc()

    async def _reconcile_started_egress_attempts() -> int:
        """Terminalize egress attempts an earlier service generation left nonterminal.

        Bounded and idempotent. Only attempts consumed strictly before this service started are
        considered, so no live dispatch is closed; each one records the exact
        ``transport_failed/outcome_unknown`` receipt it already owed. Nothing re-enters the
        provider or restores disclosure authority.
        """

        if type(privacy) is not PrivacyCoordinator:
            return 0
        return await privacy.reconcile_started_attempts(service_started_at)

    async def _reconcile_cancelled_observation_advice_semantic(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome | None:
        """Close the egress audit for an advisory attempt cancelled by a foreground rebind.

        ``None`` means no provider call can have started, so the plain ``cancelled`` row is the
        whole truth. Otherwise the call's usage is unknown (#923): the row names the provider,
        plus the consumed attempt's terminal provenance when the bounded lookup finds it, and the
        provider is never re-entered.
        """

        return await reconcile_cancelled_advice_request(
            advice_semantic_inflight.pop(attempt.attempt_id, None),
            privacy.recover_started_request if type(privacy) is PrivacyCoordinator else None,
        )

    async def _dispatch_observation_advice_semantic(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        """Privacy-gated provider attempt for one durable advice row, off the hook path (#619).

        Repository authority and the provider binding are resolved here, at dispatch time,
        never from the READY snapshot. The stored packet already carries the exact scoped
        observation gaps; nothing is rebuilt from live state. Every non-success leaves a closed
        failure reason and no finding, so the advice can only ever claim what a validated
        provider answer supports.
        """

        if not await advice_semantic_provider_ready():
            # A row queued while a provider was usable (or by an older service that scheduled
            # without one) drains here with no provider work and no rate-limit charge (#923).
            return ObservationAdviceSemanticOutcome(
                status="unavailable", failure_reason="provider_unavailable"
            )
        route = await catalog.resolve_route(attempt.yoetz_session_id)
        if (
            route is None
            or route.state is not TaskRouteState.ACTIVE
            or route.repository_privacy_commitment is None
        ):
            return ObservationAdviceSemanticOutcome(
                status="unavailable", failure_reason="authorization_missing"
            )
        repository_scope = AuthorizationScope(
            AuthorizationScopeKind.TASK,
            installation_id,
            route.repository_privacy_commitment,
            route.task_id,
        )
        if not await cast(PrivacyCoordinator, privacy).activate_repository(repository_scope):
            return ObservationAdviceSemanticOutcome(
                status="unavailable", failure_reason="authorization_missing"
            )
        binding = await resolve_provider_binding()
        if binding is None:
            return ObservationAdviceSemanticOutcome(
                status="unavailable", failure_reason="provider_unavailable"
            )
        candidate = CandidateContext(
            request_id=ids.new(IdKind.REQUEST),
            channel=EgressChannel.LLM_INFERENCE,
            local_sink=None,
            purpose=_ADVICE_SEMANTIC_PURPOSE,
            scope=repository_scope,
            subject_digest=attempt.subject_digest,
            provider_binding=binding,
            items=(
                CandidateContextItem(
                    OBSERVATION_ADVICE_PACKET_ITEM_ID,
                    DataCategory.BOUNDED_STRUCTURAL_METADATA,
                    repository_scope,
                    "/observation-advice",
                    attempt.packet_json,
                ),
            ),
        )
        deadline = Deadline(clock.now_utc(), clock.monotonic_seconds() + 60.0)
        # The supervisor runs one advisory provider attempt at a time. Remember the exact request
        # identity this dispatch minted so a foreground rebind that cancels it can reconcile the
        # consumed disclosure authorization instead of stranding it (issue #755).
        advice_semantic_inflight.clear()
        advice_semantic_inflight[attempt.attempt_id] = (candidate.request_id, binding.provider_id)
        result = await cast(PrivacyCoordinator, privacy).evaluate_semantic(candidate, deadline)
        advice_semantic_inflight.pop(attempt.attempt_id, None)
        if type(result) is not SemanticEgressSuccess:
            return ObservationAdviceSemanticOutcome(
                status="failed",
                failure_reason="provider_failed",
                provider_identity=binding.provider_id,
            )
        receipt = result.privacy_receipt_id or result.authorization_id
        judgment = result.result.judgment
        if judgment.conclusion != "challenges_returned" or not judgment.challenges:
            # Honest attempt receipt without inventing additive findings.
            return ObservationAdviceSemanticOutcome(
                status="succeeded",
                attempt_receipt=receipt,
                provider_identity=binding.provider_id,
                evidence_digest=attempt.subject_digest,
            )
        detail = f"challenges:{len(judgment.challenges)}"
        digest = canonical_digest(
            cast(
                CanonicalJsonValue,
                {
                    "basis": attempt.basis_digest,
                    "authorization_id": result.authorization_id,
                    "challenges": len(judgment.challenges),
                },
            )
        )
        finding = stable_advice_finding_id("semantic_additive_review", detail, digest)
        return ObservationAdviceSemanticOutcome(
            status="succeeded",
            attempt_receipt=receipt,
            provider_identity=binding.provider_id,
            finding_ids=(finding,),
            evidence_digest=digest,
            summaries=("Privacy-gated AI-powered observation review",),
            details=(
                "Additive AI-powered note recorded after authorized provider attempt; "
                "local findings unchanged.",
            ),
        )

    advice_semantic_supervisor = ObservationAdviceSemanticSupervisor(
        service_generation=service_generation
    )
    # The owner's switches decide whether background advice exists at all: on by default where
    # AI-powered review is configured, an explicit setting always wins (#888). Provider readiness
    # is re-read per build and per dispatch (#923). A credential or channel change takes effect
    # on the next observation; a binding change recomposes the service, never the host session.
    advice_semantic_enabled = background_advice_setting(config).enabled

    async def _close_disabled_observation_advice_semantic(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        """Close a row an earlier service queued while background advice is now off (#888).

        Startup rediscovery drains such rows here with no route, authority or provider work.
        ``cancelled`` with no provider identity records that nothing was sent, and re-enabling
        advice later never replays a packet queued under the old setting.
        """

        return ObservationAdviceSemanticOutcome(status="cancelled", failure_reason="cancelled")

    async def _advice_semantic_route_ready(yoetz_session_id: str) -> bool:
        """The route leg of background advice admission (#923).

        The dispatch needs an ACTIVE route and a granted repository authority that admits
        LLM-inference egress. Read both without the privacy admission lock (a foreground check can
        hold it for its whole provider call), so a route that cannot reach a provider writes no
        advice row at all instead of queuing one that ends ``authorization_missing``.
        """

        route = await catalog.resolve_route(yoetz_session_id)
        if (
            route is None
            or route.state is not TaskRouteState.ACTIVE
            or route.repository_privacy_commitment is None
            or privacy_application is None
        ):
            return False
        try:
            authority = await privacy_application.policy_store.repository_authority(
                AuthorizationScope(
                    AuthorizationScopeKind.TASK,
                    installation_id,
                    route.repository_privacy_commitment,
                    route.task_id,
                )
            )
        except Exception:
            # No readable repository authority is no repository authority.
            return False
        # The exact binding, purpose and scope the dispatch below sends, judged by the egress
        # pipeline's own static policy leg (938-R1): a granted authority that does not name this
        # binding or purpose would be refused at dispatch, so it admits nothing here either.
        return (
            authority.grant_state == "granted"
            and candidate_binding is not None
            and semantic_policy_refusal(
                authority.effective.policy,
                candidate_binding,
                _ADVICE_SEMANTIC_PURPOSE,
                AuthorizationScopeKind.TASK,
            )
            is None
        )

    advice_semantic_scheduler = ObservationAdviceSemanticScheduler(
        now=lambda: timestamp_from_datetime(clock.now_utc()).wire,
        enabled=advice_semantic_enabled,
        min_interval_seconds=config.observation.semantic_advice_min_interval_seconds,
        route_ready=_advice_semantic_route_ready,
        revisit=advice_semantic_supervisor.schedule_revisit,
        provider_ready=advice_semantic_provider_ready,
    )

    verification_supervisor = ObservationVerificationSupervisor(
        service_generation=service_generation
    )

    async def _project_object_store(
        task_id: str, route_generation: int
    ) -> ProjectObjectStoreLease | None:
        """Route detector details through an exact generation-bound WRITE lease."""

        route = await catalog.task_route(task_id)
        if (
            route is None
            or route.state is not TaskRouteState.ACTIVE
            or route.route_generation != route_generation
        ):
            return None
        binding = await catalog.session_binding(route.session_id)
        if binding is None or binding.task_id != task_id or binding.session_id != route.session_id:
            return None
        leased = await runtime.route(
            RouteCommand(
                route.session_id,
                binding.writer_id,
                RouteAccess.WRITE,
                frozenset({RuntimeCapability.WRITE}),
            )
        )
        if (
            type(leased) is not TaskRuntime
            or leased.task_id != task_id
            or leased.session_id != route.session_id
            or leased.writer_id != binding.writer_id
        ):
            if type(leased) is TaskRuntime:
                await runtime.release(leased)
            return None
        return ProjectObjectStoreLease(
            leased.objects,
            lambda: runtime.release(leased),
        )

    async def _workspace_consent(workspace_commitment: str) -> bool:
        """Legacy commitment-only adapter used by non-production application doubles."""

        consent = local_observation.consent_for(workspace_commitment)
        return consent is not None and consent.active

    async def _workspace_consent_for_source(task_id: str, workspace_commitment: str) -> bool:
        """Map catalog identity to observation identity through the authenticated source route.

        The catalog's workspace commitment and the observation store's local path commitment use
        different keys and domains.  A direct lookup would therefore reject every legitimate
        local consent, while trying alternate paths or digest aliases would create an authority
        bypass.  Read the encrypted session-opened locator only through the task's current,
        exact-generation PAYLOAD_READ route, verify it recomputes the catalog commitment, then
        ask the observation store about the commitment derived from that same locator.
        """

        try:
            route = await catalog.task_route(task_id)
            provenance = await catalog.task_source_provenance(task_id)
        except TypeError, ValueError, PublicOperationError:
            return False
        if (
            route is None
            or route.state is not TaskRouteState.ACTIVE
            or provenance is None
            or provenance.workspace_ref_commitment != workspace_commitment
        ):
            return False
        try:
            binding = await catalog.session_binding(route.session_id)
        except TypeError, ValueError, PublicOperationError:
            return False
        if binding is None or binding.task_id != task_id or binding.session_id != route.session_id:
            return False
        try:
            leased = await runtime.route(
                RouteCommand(
                    route.session_id,
                    binding.writer_id,
                    RouteAccess.PAYLOAD_READ,
                    frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
                )
            )
        except TypeError, ValueError, PublicOperationError:
            return False
        if (
            type(leased) is not TaskRuntime
            or leased.task_id != task_id
            or leased.session_id != route.session_id
        ):
            if type(leased) is TaskRuntime:
                await runtime.release(leased)
            return False
        try:
            opened: SessionOpenedPayload | None = None
            async for record in leased.ledger.load_events(leased.session_id):
                if isinstance(record.payload, SessionOpenedPayload):
                    opened = record.payload
                    break
            if opened is None or opened.workspace_ref is None:
                return False
            identity = await catalog.commit_identity(
                StartIdentityInput(
                    opened.task_title,
                    opened.workspace_ref,
                    opened.external_ref,
                )
            )
            if identity.workspace_ref_commitment != workspace_commitment:
                return False
            local_commitment = local_observation.workspace_commitment(opened.workspace_ref)
            consent = local_observation.consent_for(local_commitment)
            if consent is None or not consent.active:
                return False
            # The locator was read under a route lease.  Re-check its catalog identity before
            # releasing that lease so a rotation cannot turn a stale source into authority.
            latest = await catalog.task_route(task_id)
            return (
                latest is not None
                and latest.state is TaskRouteState.ACTIVE
                and latest.session_id == route.session_id
                and latest.route_generation == route.route_generation
                and latest.route_identity_digest == route.route_identity_digest
            )
        except TypeError, ValueError, PublicOperationError:
            return False
        finally:
            await runtime.release(leased)

    async def _local_workspace_commitment_for_source(task_id: str) -> str | None:
        """Resolve a task's authenticated workspace commitment without reading consent state.

        Consent revocation has already fenced the local observation store when this helper runs,
        so it cannot call ``_workspace_consent_for_source``.  It reads only the encrypted
        SessionOpened locator through the current PAYLOAD_READ route and returns the local
        commitment used by ``LocalObservationStore``; no path or task identity leaves this
        service-private callback.
        """

        def unavailable() -> PublicOperationError:
            return PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "Source consent task enumeration is unavailable.",
                retryable=True,
            )

        try:
            route = await catalog.task_route(task_id)
            provenance = await catalog.task_source_provenance(task_id)
            if route is None:
                raise unavailable()
            if route.state is not TaskRouteState.ACTIVE:
                return None
            if provenance is None:
                raise unavailable()
            binding = await catalog.session_binding(route.session_id)
            if (
                binding is None
                or binding.task_id != task_id
                or binding.session_id != route.session_id
            ):
                raise unavailable()
            leased = await runtime.route(
                RouteCommand(
                    route.session_id,
                    binding.writer_id,
                    RouteAccess.PAYLOAD_READ,
                    frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
                )
            )
            if (
                type(leased) is not TaskRuntime
                or leased.task_id != task_id
                or leased.session_id != route.session_id
            ):
                if type(leased) is TaskRuntime:
                    await runtime.release(leased)
                raise unavailable()
            try:
                opened: SessionOpenedPayload | None = None
                async for record in leased.ledger.load_events(leased.session_id):
                    if isinstance(record.payload, SessionOpenedPayload):
                        opened = record.payload
                        break
                if opened is None:
                    raise unavailable()
                if opened.workspace_ref is None:
                    if provenance.workspace_ref_commitment is None:
                        return None
                    raise unavailable()
                identity = await catalog.commit_identity(
                    StartIdentityInput(
                        opened.task_title,
                        opened.workspace_ref,
                        opened.external_ref,
                    )
                )
                if identity.workspace_ref_commitment != provenance.workspace_ref_commitment:
                    raise unavailable()
                latest = await catalog.task_route(task_id)
                if (
                    latest is None
                    or latest.state is not TaskRouteState.ACTIVE
                    or latest.session_id != route.session_id
                    or latest.route_generation != route.route_generation
                    or latest.route_identity_digest != route.route_identity_digest
                ):
                    raise unavailable()
                return local_observation.workspace_commitment(opened.workspace_ref)
            finally:
                await runtime.release(leased)
        except PublicOperationError:
            raise
        except (TypeError, ValueError) as exc:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "Source consent task enumeration is unavailable.",
                retryable=True,
            ) from exc

    async def _plan_source_consent_invalidation(
        task_ids: tuple[str, ...], workspace_commitment: str, revocation_token: str
    ) -> SourceConsentRevocationPlan:
        """Include all catalog tasks in the revoked local workspace, including unmapped tasks."""

        selected = set(task_ids)
        route_loader = getattr(catalog, "recovery_routes", None)
        if callable(route_loader):
            try:
                routes = await cast(Callable[[], Awaitable[tuple[TaskRoute, ...]]], route_loader)()
            except PublicOperationError:
                raise
            except Exception as exc:
                raise PublicOperationError(
                    PublicErrorCode.SERVICE_UNAVAILABLE,
                    "Source consent task enumeration is unavailable.",
                    retryable=True,
                ) from exc
            if type(routes) is not tuple or any(type(route) is not TaskRoute for route in routes):
                raise PublicOperationError(
                    PublicErrorCode.SERVICE_UNAVAILABLE,
                    "Source consent task enumeration is unavailable.",
                    retryable=True,
                )
            for route in routes:
                if route.state is not TaskRouteState.ACTIVE:
                    continue
                if route.task_id in selected:
                    continue
                mapped = await _local_workspace_commitment_for_source(route.task_id)
                if mapped == workspace_commitment:
                    selected.add(route.task_id)
        application = project_application
        if application is None:
            raise RuntimeError("project_application_unavailable")
        return await application.plan_source_workspace_consent_invalidation(
            tuple(sorted(selected, key=str.encode)), revocation_token
        )

    project_catalog = cast(ProjectCatalogPort, catalog)
    project_text_store = build_routed_project_text_store(
        runtime=runtime,
        catalog=project_catalog,
        clock=clock,
    )

    async def _project_text_disclosure_authorizer(
        owner_task_id: str,
        owner_workspace_commitment: str,
        field: Literal["title", "description"],
        sink: object,
        purpose: str,
    ) -> bool:
        """Check source-owner policy before a project text object is opened."""

        del field, purpose
        if not isinstance(sink, LocalDisclosureSink):
            return False
        if privacy_application is None:
            return False
        try:
            scope = AuthorizationScope(
                AuthorizationScopeKind.TASK,
                installation_id,
                owner_workspace_commitment,
                owner_task_id,
            )
            effective = await privacy_application.policy_store.effective_policy(scope)
        except Exception:
            return False
        # Both project fields are owner-authored task-description content. The local human sink
        # has the established local-view ceiling; every agent/model/control sink must be allowed
        # by the source owner's effective policy before the encrypted object is read.
        policy = effective.policy
        if sink is LocalDisclosureSink.LOCAL_HUMAN_VIEW:
            return True
        if sink is LocalDisclosureSink.AGENT_CONTEXT:
            return (
                DataCategory.TASK_DESCRIPTION in policy.agent_context_categories
                and DataClass.ORDINARY_USER_CONTENT in policy.agent_context_data_classes
            )
        if sink is LocalDisclosureSink.LOCAL_MODEL:
            return (
                policy.local_model_enabled
                and DataCategory.TASK_DESCRIPTION in policy.local_model_categories
                and DataClass.ORDINARY_USER_CONTENT in policy.local_model_data_classes
            )
        return (
            DataCategory.TASK_DESCRIPTION in policy.trusted_human_control_categories
            and DataClass.ORDINARY_USER_CONTENT in policy.trusted_human_control_data_classes
        )

    async def _project_coordination_source_authorizer(
        source_task_id: str,
        source_workspace_commitment: str,
        project_id_value: str,
    ) -> bool:
        """Authorize bounded coordination facts under the source task's live policy.

        Coordination is an ``other_writer`` agent-context disclosure.  The source must therefore
        explicitly allow the structural and finding-summary categories used by the detector and
        must retain the public-structural class.  Project membership/grant and source workspace
        consent remain separate checks in ``ProjectApplication.admit``; this callback supplies
        only the effective policy/scope decision and fails closed when READY is incomplete.
        """

        del project_id_value
        if privacy_application is None:
            return False
        try:
            scope = AuthorizationScope(
                AuthorizationScopeKind.TASK,
                installation_id,
                source_workspace_commitment,
                source_task_id,
            )
            effective = await privacy_application.policy_store.effective_policy(scope)
        except Exception:
            return False
        policy = effective.policy
        required_categories = {
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.FINDING_SUMMARY,
        }
        return required_categories.issubset(set(policy.agent_context_categories)) and (
            DataClass.PUBLIC_STRUCTURAL in set(policy.agent_context_data_classes)
        )

    async def _project_coordination_resource_disclosure_authorizer(
        owner_task_id: str,
        owner_workspace_commitment: str,
        sink: object,
        purpose: str,
    ) -> bool:
        """Authorize source-owned relative resources for the requested local sink.

        A coordination detail can contain declarations from both participants; the application
        invokes this callback once per source before opening the encrypted object.  Relative paths
        are repository excerpts, so the source policy must authorize ordinary user content rather
        than the structural admission categories used for detection identities.
        """

        del purpose
        if not isinstance(sink, LocalDisclosureSink) or privacy_application is None:
            return False
        try:
            scope = AuthorizationScope(
                AuthorizationScopeKind.TASK,
                installation_id,
                owner_workspace_commitment,
                owner_task_id,
            )
            effective = await privacy_application.policy_store.effective_policy(scope)
        except Exception:
            return False
        policy = effective.policy
        if sink is LocalDisclosureSink.LOCAL_HUMAN_VIEW:
            return True
        if sink is LocalDisclosureSink.AGENT_CONTEXT:
            return (
                DataCategory.REPOSITORY_EXCERPT in policy.agent_context_categories
                and DataClass.ORDINARY_USER_CONTENT in policy.agent_context_data_classes
            )
        if sink is LocalDisclosureSink.LOCAL_MODEL:
            return (
                policy.local_model_enabled
                and DataCategory.REPOSITORY_EXCERPT in policy.local_model_categories
                and DataClass.ORDINARY_USER_CONTENT in policy.local_model_data_classes
            )
        return (
            DataCategory.REPOSITORY_EXCERPT in policy.trusted_human_control_categories
            and DataClass.ORDINARY_USER_CONTENT in policy.trusted_human_control_data_classes
        )

    project_application = ProjectApplication(
        project_catalog,
        ids=ids,
        clock=clock,
        operation_journal=SqliteProjectOperationJournal(
            cast(apsw.Connection, getattr(catalog, "_db")),
            installation_id=installation_id,
        ),
        operation_digest=lambda identity: lookup.mac(
            PROJECT_OPERATION_MAC_DOMAIN,
            canonical_encode(identity),
        ),
        text_store=cast(ProjectTextStore, project_text_store),
        workspace_consent=_workspace_consent,
        workspace_consent_for_source=_workspace_consent_for_source,
        grant_authorizer=ProjectCoordinationGrantAuthority(state_path=paths.state),
        text_disclosure_authorizer=_project_text_disclosure_authorizer,
        coordination_source_authorizer=_project_coordination_source_authorizer,
        coordination_resource_disclosure_authorizer=(
            _project_coordination_resource_disclosure_authorizer
        ),
    )
    coordination_detail_store = _RoutedCoordinationDetailStore(
        _project_object_store,
        clock=clock,
    )
    coordination_runtime = build_coordination_runtime(
        projects=project_application,
        runtime=runtime,
        catalog_db=cast(apsw.Connection, getattr(catalog, "_db")),
        clock=clock,
        detail_store=coordination_detail_store,
    )
    # Project status and coordination admission share the durable delivery adapter created by
    # the production coordination factory; no in-memory detector is allowed in READY.
    project_application.detection_store = coordination_runtime.detector.store
    project_application.coordination_detail_reader = coordination_detail_store
    # The detector is service-internal today; retain it on the composed application for the
    # observation/input producer and future maintenance runner without widening the control API.
    setattr(project_application, "coordination_detector", coordination_runtime.detector)
    setattr(project_application, "coordination_runtime", coordination_runtime)
    setattr(project_application, "coordination_input_provider", coordination_runtime.inputs)

    async def sweep_coordination() -> tuple[object, ...]:
        """Retry durable coordination discovery and delivery for every live project.

        Accepted publishes trigger a task-local sweep.  This bounded maintenance pass covers
        projects whose detector write or delivery failed after the ledger append, and discovers
        pairs whose second task published while the service was restarting.  Project/task
        selection comes only from the authenticated catalog routes; no workspace scan or caller
        supplied path is involved.
        """

        project_ids: set[str] = set()
        project_loader = getattr(catalog, "list_project_ids", None)
        if callable(project_loader):
            try:
                project_ids = set(
                    await cast(Callable[[], Awaitable[tuple[str, ...]]], project_loader)()
                )
            except Exception:
                project_ids = set()
        else:
            route_loader = getattr(catalog, "recovery_routes", None)
            if not callable(route_loader):
                return ()
            routes = await cast(Callable[[], Awaitable[tuple[TaskRoute, ...]]], route_loader)()
            for route in routes:
                if type(route) is not TaskRoute or route.state is not TaskRouteState.ACTIVE:
                    continue
                try:
                    project_ids.update(await catalog.list_task_project_ids(route.task_id))
                except Exception:
                    continue
        outputs: list[object] = []
        for project_id_value in sorted(project_ids, key=str.encode):
            try:
                outputs.extend(await coordination_runtime.sweep(project_id_value=project_id_value))
            except Exception:
                # One stale or revoked project cannot starve retries for the remaining projects.
                continue
        return tuple(outputs)

    if lineage_semantic_gate is not None:
        # The semantic gate is created before the project facade below so the evaluator closure
        # can be composed with the rest of the provider path.  Bind the exact current facade once
        # its routed encrypted stores are ready; the mutable gate itself is service-private.
        lineage_semantic_gate.project_admission = project_application
    lineage_manifest_coordinator = LineageManifestCoordinator(
        runtime=runtime,
        catalog=catalog,
        clock=clock,
        ids=ids,
        source_gate=(
            None
            if privacy_application is None
            else PrivacyLineageSourceGate(
                privacy_application.policy_store,
                installation_id,
                project_admission=project_application,
                project_resolver=_shared_lineage_project,
            )
        ),
    )
    # Hooks deliberately avoid loading the full service config.  Publish the exact
    # config snapshot owned by this fresh READY generation before it can receive
    # observation RPCs; malformed/unsafe markers fail closed in hook processes.
    local_observation.set_runtime_enabled(config.observation.enabled)

    observation_coordinator = ObservationCoordinator(
        runtime=runtime,
        local=local_observation,
        clock=clock,
        ids=ids,
        state_root=paths.state,
        consent_invalidation_planner=_plan_source_consent_invalidation,
        consent_invalidation_applier=project_application.apply_source_workspace_consent_invalidation,
        advice_context_builder=ObservationAdviceContextBuilder(
            composition=observation_composition_fact,
            semantic_scheduler=advice_semantic_scheduler if advice_semantic_enabled else None,
        ),
        verification_supervisor=verification_supervisor,
        advice_semantic_supervisor=advice_semantic_supervisor,
        advice_semantic_dispatch=(
            _dispatch_observation_advice_semantic
            if advice_semantic_enabled
            else _close_disabled_observation_advice_semantic
        ),
        advice_semantic_cancellation_reconciler=_reconcile_cancelled_observation_advice_semantic,
        observation_enabled=config.observation.enabled,
        lineage_coordinator=lineage_manifest_coordinator,
        host_lineage_registry=host_lineage_registry,
        observed_host_session_binding=observed_host_session_binding(catalog, lineage),
        observed_activity_hook=observed_activity_renewal(catalog, lineage, clock),
        capture_budget_bootstrap=bootstrap_capture_reservations,
        capture_handoff_reconcile=reconcile_capture_handoffs,
    )
    if advice_semantic_enabled:
        advice_semantic_supervisor.set_revisit_handler(
            observation_coordinator.revisit_advice_semantic
        )
    observation_sweeper = ObservationOutboxSweeper(
        local_observation,
        observation_coordinator,
        budget_seconds=DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS,
        ingest_gate=observation_gate,
        capture_recovery=observation_coordinator.recover_capture_inventory,
    )
    legacy_spool_forwarder = _LegacyHookSpoolForwarder(paths.state)

    async def sweep_lineage_manifests() -> tuple[object, ...]:
        """Refresh recorded manifests after public task activity.

        Hook ingestion already invokes the lineage lane for the task it touches. Public
        ``publish_work`` has no observation envelope, so the normal maintenance hook also walks
        authenticated task routes deepest-first. Each parent sweep remains service-side and
        bounded; deepest-first ordering lets a grandchild move its child's manifest before the
        parent observes that child's new frontier.
        """

        route_loader = getattr(catalog, "recovery_routes", None)
        if not callable(route_loader):
            return ()
        try:
            routes = await cast(Callable[[], Awaitable[tuple[TaskRoute, ...]]], route_loader)()
        except Exception:
            return ()
        outputs: list[object] = []
        ordered = tuple(
            sorted(
                (
                    route
                    for route in routes
                    if type(route) is TaskRoute and route.state is TaskRouteState.ACTIVE
                ),
                key=lambda route: (-route.depth, str(route.task_id).encode("ascii")),
            )
        )
        for route in ordered:
            try:
                result = await lineage_manifest_coordinator.sweep_task(route.task_id)
            except Exception:
                continue
            if result is not None:
                outputs.append(result)
        return tuple(outputs)

    async def sweep_observation() -> ObservationDrainSummary:
        """Move fenced legacy-hook spool records into the normal durable outbox.

        Replaying a claimed file after a daemon crash is safe: each spool UUID is
        part of the hook source identity, so local ingest deduplicates it before
        the ordinary service-owned outbox sweep forwards it.
        """

        # The forwarding worker owns the spool claim and its executor.  Keeping it outside the
        # event loop preserves the mainline cancellation boundary; lineage refresh then runs after
        # ordinary observation ingestion so the same maintenance pass sees the newest task state.
        await legacy_spool_forwarder.replay()
        summary = await observation_sweeper.sweep()
        await sweep_lineage_manifests()
        return summary

    def close_observation_maintenance() -> None:
        legacy_spool_forwarder.close()
        observation_sweeper.close()
        observation_coordinator.close()

    async def refresh_ready_recommendations() -> object:
        # READY has no exact selected-Codex-home identity.  Never infer the
        # normal ambient home while an isolated host may own this daemon.
        activation_state: str | None = None
        context = await evaluate_recommendation_context(
            observation_enabled=config.observation.enabled,
            codex_activation_state=activation_state,
            policy=policy,
            allow_network=True,
            cache_root=paths.state,
        )
        return await refresh_pending(context=context, root=paths.state)

    observation_handlers = build_observation_support_handlers(observation_coordinator)
    support_handlers: dict[ControlMethod, Callable[..., Awaitable[JsonObject]]] = dict(
        cast(Mapping[ControlMethod, Callable[..., Awaitable[JsonObject]]], observation_handlers)
    )
    privacy_app = cast(PrivacyCoordinator, privacy).policy_application
    if privacy_app is not None:
        support_handlers.update(build_privacy_support_handlers(privacy_app))
    project_handlers = cast(
        Mapping[ControlMethod, Callable[..., Awaitable[JsonObject]]],
        build_project_support_handlers(
            project_application,
            control_method=ControlMethod.PROJECT,
        ),
    )
    support_handlers.update(project_handlers)

    import_publication_authority = ImportPublicationAuthority(state_path=paths.state)
    return ServiceReadyContext(
        service_generation=service_generation,
        vault_generation=vault_generation,
        generation_is_current=generation_is_current,
        start_catalog=catalog,
        publish_responses=catalog,
        runtime=runtime,
        clock=clock,
        ids=ids,
        verification_policy=VerificationPolicy(
            semantic=config.verification.semantic,
            max_findings=config.verification.max_findings,
            finding_attempt_budget=config.verification.finding_attempt_budget,
        ),
        privacy=privacy,  # pyright: ignore[reportArgumentType]
        status_cursor_key=os.urandom(32),
        waiver_policy_digest=policy.policy_digest,
        semantic_evaluator=semantic_evaluator,
        disclosure_scope_for=disclosure_scope_for,
        receipt_version_resolver=lambda _: versions,
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=import_publication_authority,
        profile=_profile(config),
        policy_packs=_policy_packs(manifest),
        version_manifest=manifest,
        support_handlers=support_handlers,
        verification_supervisor=verification_supervisor,
        rediscover_pending_verification=observation_coordinator.rediscover_pending_verification,
        advice_semantic_supervisor=advice_semantic_supervisor,
        rediscover_pending_advice_semantic=(
            observation_coordinator.rediscover_pending_advice_semantic
        ),
        reconcile_started_egress_attempts=_reconcile_started_egress_attempts,
        connected_provider_ids=connected_provider_ids,
        provider_credential_connected=provider_credential_connected,
        fallback_credential_connected=fallback_credential_connected,
        semantic_ready=semantic_ready,
        observation_sweep=_ReadyObservationSweep(
            sweep_observation,
            row_gate_bound=observation_gate is not None,
            backlog_probe=local_observation.has_unattempted_outbox_rows,
            task_pending_probe=_task_pending_probe(local_observation, paths.state),
        ),
        coordination_sweep=sweep_coordination,
        observation_sweep_close=close_observation_maintenance,
        ready_recommendation_refresh=refresh_ready_recommendations,
        reconcile_observation_capture=reconcile_observation_capture,
        lineage=lineage,
        project_application=project_application,
        host_lineage_registry=host_lineage_registry,
        reconcile_observation_losses=observation_coordinator.reconcile_task_selection_losses,
        change_capture=change_capture,
    )


def build_ready_application_factory(
    *,
    lifecycle: _Lifecycle,
    vault: _Vault,
    config: YoetzConfig,
    paths: _Paths,
    clock: ClockPort,
    secret_memory: object,
    diagnostics: DiagnosticsPort | None = None,
    observation_gate: asyncio.Lock | None = None,
    startup_bundle_upgrade: _StartupBundleUpgrade | None = None,
) -> ReadyApplicationFactory:
    upgrade = startup_bundle_upgrade
    if upgrade is None:
        upgrade = _build_default_startup_bundle_upgrade(
            lifecycle=lifecycle,
            vault=vault,
            config=config,
            paths=paths,
            secret_memory=secret_memory,
        )
    # Publish the loaded config gate before unlock/READY construction begins;
    # hooks then stop capture during a disabled service generation as well as
    # after it reaches READY.
    LocalObservationStore(_state=paths.state).set_runtime_enabled(config.observation.enabled)
    return ReadyApplicationFactory(
        context_provider=lambda service_generation, vault_generation: provide_service_ready_context(
            service_generation,
            vault_generation,
            lifecycle=lifecycle,
            vault=vault,
            config=config,
            paths=paths,
            clock=clock,
            secret_memory=secret_memory,
            diagnostics=diagnostics,
            observation_gate=observation_gate,
            startup_bundle_upgrade=upgrade,
        )
    )
