"""Local-control live Codex observation boundary."""

from __future__ import annotations

from typing import Protocol

from finishup.domain.observation import (
    AdviceItem,
    AdviceSnapshot,
    ObservationCaptureBacklog,
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationContentManifest,
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationInspectionSnapshot,
    ObservationLifecycle,
    ObservationRevokeCommand,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
    observation_earns_hook_observed,
    workspace_commitment_from_path,
)
from finishup.domain.observation_loss import ObservationSelectionLoss
from finishup.domain.values import Timestamp
from finishup.kernel.policies.observation_advice import ObservationCheckFact
from finishup.ports.objects import ObjectRef
from finishup.ports.observation_errors import ObservationStoreLockTimeout

__all__ = [
    "AdviceItem",
    "AdviceSnapshot",
    "ObservationControlCommand",
    "ObservationCaptureBacklog",
    "ObservationContentChunk",
    "ObservationContentManifest",
    "ObservationCaptureTicket",
    "ObservationContentKind",
    "ObservationCursor",
    "ObservationEnvelope",
    "ObservationGapCode",
    "ObservationIngestDisposition",
    "ObservationIngestResult",
    "ObservationInspectionSnapshot",
    "ObservationLogicalIdentityClaim",
    "ObservationLifecycle",
    "ObservationPort",
    "ObservationRevokeCommand",
    "ObservationSource",
    "ObservationStatus",
    "ObservationStatusQuery",
    "ObservationStoreLockTimeout",
    "TaskObservationPort",
    "observation_earns_hook_observed",
    "workspace_commitment_from_path",
]

type ObservationLogicalIdentityClaim = tuple[str, str, str]


class ObservationPort(Protocol):
    async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult: ...

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus: ...

    async def pause(self, command: ObservationControlCommand) -> ObservationStatus: ...

    async def resume(self, command: ObservationControlCommand) -> ObservationStatus: ...

    async def revoke(self, command: ObservationRevokeCommand) -> ObservationStatus: ...


class TaskObservationPort(Protocol):
    """Durable, mapped-task observation store exposed on a WRITE ``TaskRuntime``.

    This is the least-authority seam production code uses instead of reaching
    into a ledger adapter's private connection. It carries exactly the durable
    observation-store operations the coordinator needs to persist envelopes,
    read back coverage, and record advice snapshots for one mapped task bundle.
    """

    def grant_consent(
        self,
        workspace_commitment: str,
        granted_at: Timestamp,
        *,
        content_capture_profiles: tuple[str, ...] = (),
    ) -> None: ...

    def content_capture_profiles(self, workspace_commitment: str) -> tuple[str, ...]: ...

    def enable_content_capture(self, workspace_commitment: str, profile: str) -> None: ...

    def disable_content_capture(
        self, workspace_commitment: str, profile: str | None = None
    ) -> None: ...

    def bind_session(self, workspace_commitment: str, session_commitment: str) -> None: ...

    async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult: ...

    async def record_selection_loss(
        self, workspace: str, loss: ObservationSelectionLoss, observed_at: Timestamp
    ) -> None: ...

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus: ...

    async def revoke(self, command: ObservationRevokeCommand) -> ObservationStatus: ...

    def list_envelopes(
        self, workspace: str, *, limit: int | None = None
    ) -> tuple[ObservationEnvelope, ...]: ...

    def set_advice_snapshot(
        self, workspace: str, snapshot: AdviceSnapshot, updated_at: Timestamp
    ) -> None: ...

    def load_advice_snapshot(self, workspace: str) -> AdviceSnapshot | None: ...

    def load_advice_snapshot_for_session(
        self, *, workspace: str, yoetz_session_id: str
    ) -> AdviceSnapshot | None: ...

    def set_session_advice_snapshot(
        self,
        *,
        workspace: str,
        yoetz_session_id: str,
        snapshot: AdviceSnapshot,
        updated_at: Timestamp,
    ) -> None: ...

    def load_latest_advice_snapshot(self) -> AdviceSnapshot | None: ...

    def workspace_for_finishup_session(self, yoetz_session_id: str) -> str | None: ...

    def record_workspace_session_route(
        self,
        *,
        workspace: str,
        yoetz_session_id: str,
        yoetz_task_id: str,
        yoetz_writer_id: str,
        codex_session_commitment: str,
        bound_at: Timestamp,
    ) -> bool: ...

    def record_inspection_snapshot(
        self,
        *,
        workspace: str,
        yoetz_session_id: str,
        subject_state_digest: str,
        changed_paths_digest: str,
        relative_paths: tuple[str, ...],
        facts_ref: ObjectRef | None,
        facts_content_digest: str | None,
        facts_content_bytes: int | None,
        excerpt_ref: ObjectRef | None,
        excerpt_content_digest: str | None,
        excerpt_content_bytes: int | None,
        excerpt_redacted: bool,
        excerpt_truncated: bool,
        recorded_at: Timestamp,
    ) -> None: ...

    def load_inspection_snapshot(
        self,
        *,
        workspace: str,
        yoetz_session_id: str,
        subject_state_digest: str,
    ) -> ObservationInspectionSnapshot | None: ...

    def record_advice_history(
        self,
        *,
        workspace: str,
        snapshot: AdviceSnapshot,
        verification_state: str,
        semantic_state: str,
        freshness: str,
        recorded_at: Timestamp,
    ) -> None: ...

    def record_content_manifest(
        self,
        *,
        workspace: str,
        logical_identity: str,
        chunk: ObservationContentChunk,
        ref: ObjectRef,
        content_digest: str,
        content_bytes: int,
        recorded_at: Timestamp,
    ) -> None: ...

    def content_manifest_object_id(
        self,
        *,
        workspace: str,
        logical_identity: str,
        chunk: ObservationContentChunk,
    ) -> str | None: ...

    def content_manifests_for_logical_identity(
        self,
        *,
        workspace: str,
        logical_identity: str,
        correlation_identity_prefix: str | None = None,
    ) -> tuple[ObservationContentManifest, ...]: ...

    def load_content_manifest(self, object_id: str) -> ObservationContentManifest | None: ...

    def capture_backlog(self, workspace: str) -> ObservationCaptureBacklog: ...

    def record_capture_ticket(self, ticket: ObservationCaptureTicket) -> None: ...

    def finalize_capture_ticket(
        self,
        staging_ticket: ObservationCaptureTicket,
        complete_ticket: ObservationCaptureTicket,
    ) -> None: ...

    def load_capture_ticket(
        self, *, workspace: str, logical_identity: str
    ) -> ObservationCaptureTicket | None: ...

    def delete_capture_ticket(self, ticket: ObservationCaptureTicket) -> None: ...

    def tombstone_capture_ticket(self, ticket: ObservationCaptureTicket) -> None: ...

    def structural_envelope_accepted(
        self, workspace: str, envelope: ObservationEnvelope
    ) -> bool: ...

    def bind_workspace_locator(
        self,
        *,
        workspace: str,
        locator_ref: ObjectRef,
        bound_at: Timestamp,
    ) -> None: ...

    def workspace_locator_descriptor(self, workspace: str) -> tuple[str, str] | None: ...

    def record_trusted_check_policy(
        self,
        *,
        workspace: str,
        policy_digest: str,
        trust_ref: ObjectRef,
        trusted_at: Timestamp,
    ) -> None: ...

    def policy_digest_is_trusted(self, workspace: str, policy_digest: str) -> bool: ...

    def latest_verification_subject_digest(self, workspace: str) -> str | None: ...

    def load_check_facts(self, workspace: str) -> tuple[ObservationCheckFact, ...]: ...

    def verification_repository(self) -> object: ...

    def advice_semantic_repository(self) -> object: ...

    def record_logical_identity_claim(
        self,
        *,
        workspace: str,
        logical_identity: str,
        materialization_digest: str,
        operation_id: str,
        source_mask: int,
        mapping_version: str,
        materialized_at: Timestamp,
    ) -> None: ...

    def load_logical_identity_claim(
        self, *, workspace: str, logical_identity: str
    ) -> ObservationLogicalIdentityClaim | None: ...
