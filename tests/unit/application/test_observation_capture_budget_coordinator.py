"""Coordinator handling for explicit native capture budget exhaustion."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest

from finishup.adapters.integrations.codex_lifecycle import LifecycleMapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.domain.observation import (
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationContentManifest,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.ports.observation import TaskObservationPort
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id

_COMMITMENT = "hmac-sha256:" + "c" * 64
_DIGEST = "sha256:" + "d" * 64


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 9, 10, tzinfo=UTC)


class _Store:
    def __init__(self) -> None:
        self.envelopes: list[ObservationEnvelope] = []
        self.tombstoned: list[object] = []

    def grant_consent(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def bind_session(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def tombstone_capture_ticket(self, ticket: object) -> None:
        self.tombstoned.append(ticket)

    async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
        self.envelopes.append(envelope)
        return ObservationIngestResult(
            ObservationIngestDisposition.ACCEPTED,
            None,
            envelope.cursor,
        )


def _fixture(tmp_path: Path) -> tuple[ObservationCoordinator, _Store, str, LifecycleMapping]:
    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    codex_session_id = f"capture-budget-{uuid4()}"
    session_commitment = local.bind_codex_session(workspace, codex_session_id)
    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=codex_session_id,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    store = _Store()
    runtime = SimpleNamespace(
        task_id=mapping.finishup_task_id,
        session_id=mapping.finishup_session_id,
        writer_id=mapping.finishup_writer_id,
        observation=store,
    )

    class _Runtime:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            assert released is runtime

    coordinator = ObservationCoordinator(
        runtime=_Runtime(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # type: ignore[reportUnknownLambdaType]
    )
    return coordinator, store, session_commitment, mapping


def _envelope(session_commitment: str, *, identity: str) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session_commitment,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            1,
            0,
            1,
            f"hmac-sha256:{'ab' * 32}",
            "codex-obs-hook/1.0.0",
        ),
        receipt_time=Timestamp("2026-09-10T00:00:00.000Z"),
        structural_payload=JsonObject(
            {
                "tool_name": "shell",
                "tool_call_id": "capture-budget-call",
                "exit_status": 1,
            }
        ),
        content_object_refs=(),
        gap_codes=(),
    )


def _chunk() -> ObservationContentChunk:
    return ObservationContentChunk(
        content_kind=ObservationContentKind.TOOL_OUTPUT,
        correlation_identity="capture-budget-call",
        source_commitment=f"hmac-sha256:{'cd' * 32}",
        media_type="text/plain",
        part_index=0,
        part_count=1,
        content=b"captured",
        redacted=False,
    )


class _ManifestStore:
    def __init__(self, manifests: tuple[ObservationContentManifest, ...]) -> None:
        self.manifests = manifests

    def content_manifests_for_logical_identity(
        self,
        *,
        workspace: str,
        logical_identity: str,
        correlation_identity_prefix: str | None = None,
    ) -> tuple[ObservationContentManifest, ...]:
        del workspace, logical_identity, correlation_identity_prefix
        return self.manifests


def _reservation_ticket(
    task_id: str, *, object_ids: tuple[str, ...] = ()
) -> ObservationCaptureTicket:
    return ObservationCaptureTicket(
        workspace_commitment=_COMMITMENT,
        task_id=task_id,
        finishup_session_id=new_id(IdKind.SESSION),
        session_commitment=_COMMITMENT,
        source=ObservationSource.CODEX_HOOK,
        source_identity="capture-reservation",
        cursor=ObservationCursor(
            1,
            0,
            1,
            _COMMITMENT,
            "codex-obs-hook/1.0.0",
        ),
        logical_identity="capture-reservation-identity",
        content_capture_profile=None,
        authority_generation=_DIGEST,
        object_ids=object_ids,
        captured_at=Timestamp("2026-09-10T00:00:00.000Z"),
        state="staging",
    )


def test_partial_capture_retry_deduplicates_parts_before_global_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.adapters.integrations.observation_local as local_mod
    import finishup.application.observation_coordinator as coordinator_mod

    monkeypatch.setattr(local_mod, "_MAX_CAPTURE_CONTENT_BYTES", 10)
    monkeypatch.setattr(coordinator_mod, "_MAX_CAPTURE_CONTENT_BYTES", 10)
    first = LocalObservationStore(_state=tmp_path)
    second = LocalObservationStore(_state=tmp_path)
    workspace = first.workspace_commitment(str(tmp_path.resolve()))
    first_ticket_id = "sha256:" + "a" * 64
    second_ticket_id = "sha256:" + "b" * 64
    first_task = new_id(IdKind.TASK)
    second_task = new_id(IdKind.TASK)
    first_ticket = _reservation_ticket(first_task)
    first_chunk = replace(_chunk(), content=b"1234567", part_count=2)
    second_chunk = replace(_chunk(), content=b"890", part_index=1, part_count=2)

    initial = ObservationCoordinator._capture_ticket_reservation_bytes(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast(TaskObservationPort, _ManifestStore(())),
        workspace=workspace,
        ticket=first_ticket,
        chunks=(first_chunk,),
    )
    assert initial == 7
    first.reserve_capture_ticket(workspace, first_ticket_id, first_task, initial)
    first.confirm_capture_ticket_reservation(workspace, first_ticket_id, first_task)

    retained_object_id = new_id(IdKind.OBJECT)
    retained = ObservationContentManifest(
        object_id=retained_object_id,
        envelope_digest=_DIGEST,
        content_kind=first_chunk.content_kind,
        part_index=first_chunk.part_index,
        part_count=first_chunk.part_count,
        redacted=False,
        content_digest="sha256:" + hashlib.sha256(first_chunk.content).hexdigest(),
        content_bytes=len(first_chunk.content),
        correlation_identity=first_chunk.correlation_identity,
        source_commitment=first_chunk.source_commitment,
    )
    retry_ticket = replace(first_ticket, object_ids=(retained_object_id,))
    retry_bytes = ObservationCoordinator._capture_ticket_reservation_bytes(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast(TaskObservationPort, _ManifestStore((retained,))),
        workspace=workspace,
        ticket=retry_ticket,
        chunks=(first_chunk, second_chunk),
    )
    assert retry_bytes == 10
    first.reserve_capture_ticket(workspace, first_ticket_id, first_task, retry_bytes)

    second_bytes = ObservationCoordinator._capture_ticket_reservation_bytes(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast(TaskObservationPort, _ManifestStore(())),
        workspace=workspace,
        ticket=_reservation_ticket(second_task),
        chunks=(replace(_chunk(), content=b"x"),),
    )
    with pytest.raises(PublicOperationError) as exhausted:
        second.reserve_capture_ticket(workspace, second_ticket_id, second_task, second_bytes)
    assert exhausted.value.code is PublicErrorCode.LIMIT_EXCEEDED


@pytest.mark.anyio
async def test_missing_capture_inventory_callback_refuses_before_reservation(
    tmp_path: Path,
) -> None:
    coordinator, store, _session_commitment, mapping = _fixture(tmp_path)
    local = coordinator.local
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    task_runtime = cast(TaskRuntime, SimpleNamespace(task_id=mapping.finishup_task_id))

    with pytest.raises(PublicOperationError) as refused:
        await coordinator._reserve_capture_ticket(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            workspace,
            task_runtime,
            cast(TaskObservationPort, store),
            _reservation_ticket(mapping.finishup_task_id),
            8,
        )

    assert refused.value.code is PublicErrorCode.LIMIT_EXCEEDED
    backlog = local.capture_backlog(workspace)
    assert backlog["capture_backlog_scope"] == "unknown"
    assert backlog["count"] == 0
    assert backlog["byte_count"] == 0


@pytest.mark.anyio
async def test_capture_budget_error_has_explicit_negative_reason(tmp_path: Path) -> None:
    coordinator, _store, session_commitment, mapping = _fixture(tmp_path)

    class _BudgetCoordinator(ObservationCoordinator):
        async def _native_capture_context(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> object:
            del args, kwargs
            raise PublicOperationError(
                PublicErrorCode.LIMIT_EXCEEDED,
                "Observation captured-content byte budget is exhausted.",
                retryable=False,
            )

    coordinator = _BudgetCoordinator(
        runtime=coordinator.runtime,
        local=coordinator.local,
        clock=coordinator.clock,
        ids=coordinator.ids,
        state_root=tmp_path,
        mapping_loader=coordinator.mapping_loader,
    )
    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=_envelope(session_commitment, identity="capture-budget-only"),
            content_chunks=(_chunk(),),
            capture_only=True,
        )
    )

    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value
    assert result.reason != ObservationGapCode.LEDGER_REJECTED.value


@pytest.mark.anyio
@pytest.mark.parametrize("stage", ["prepare", "capture"])
async def test_structural_row_keeps_both_capture_budget_gaps(tmp_path: Path, stage: str) -> None:
    coordinator, store, session_commitment, mapping = _fixture(tmp_path)
    envelope = _envelope(session_commitment, identity="capture-budget-structural")
    staging_ticket = replace(
        _reservation_ticket(mapping.finishup_task_id),
        workspace_commitment=coordinator.local.workspace_commitment(str(tmp_path.resolve())),
        finishup_session_id=mapping.finishup_session_id,
        session_commitment=session_commitment,
        source_identity=envelope.source_identity,
        cursor=envelope.cursor,
        logical_identity="capture-budget",
    )

    class _BudgetCoordinator(ObservationCoordinator):
        async def _native_capture_context(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> object:
            del args, kwargs
            if stage == "prepare":
                raise PublicOperationError(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "Observation capture reservation budget is exhausted.",
                    retryable=False,
                )
            return SimpleNamespace(
                native_source=True,
                content_identity="capture-budget",
                content_authorized=True,
                content_authorization_missing=False,
                content_capture_blocked=False,
                capture_ticket_revoked=False,
                capture_fence=None,
                fence_generation=None,
                capture_staging_ticket=staging_ticket,
                staged_ticket=None,
                expected_capture_parts=None,
                rejection_reason=None,
            )

        async def _capture_content(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> object:
            del args, kwargs
            self._capture_budget_exhausted = True
            return (), (), False, True

        async def _append_materialized(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            return None

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    budget_coordinator = _BudgetCoordinator(
        runtime=coordinator.runtime,
        local=coordinator.local,
        clock=coordinator.clock,
        ids=coordinator.ids,
        state_root=tmp_path,
        mapping_loader=coordinator.mapping_loader,
    )
    result = await budget_coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=envelope,
            content_chunks=(_chunk(),),
        )
    )

    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    assert len(store.envelopes) == 1
    assert len(store.tombstoned) == (0 if stage == "prepare" else 1)
    assert store.envelopes[0].gap_codes == (
        ObservationGapCode.CAPTURE_BUDGET_EXHAUSTED.value,
        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
    )
