"""Fence native content when consent changes during object finalization."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import apsw
import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.application.observation_materialize import observation_content_identity
from finishup.domain.observation import (
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationSource,
)
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.domain.values import JsonObject, Timestamp
from finishup.ports.objects import ObjectMetadata, ObjectRef, ObjectSource
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

_TASK = "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_COMMITMENT = "hmac-sha256:" + "c" * 64
_DIGEST = "sha256:" + "d" * 64
_WORKSPACE = "hmac-sha256:" + "1" * 64


class _ProfileMismatchStore:
    def __init__(self, ticket: ObservationCaptureTicket) -> None:
        self.ticket = ticket
        self.tombstones: list[tuple[str, str | None]] = []

    def capture_ticket_schema_available(self) -> bool:
        return True

    def load_capture_ticket(self, **_kwargs: object) -> ObservationCaptureTicket:
        return self.ticket

    def content_capture_profiles(self, _workspace: str) -> tuple[str, ...]:
        return ()

    def tombstone_capture_tickets(self, workspace: str, profile: str | None = None) -> None:
        self.tombstones.append((workspace, profile))


class _NoAuthorityLocal:
    def content_capture_authority(self, _workspace: str) -> None:
        return None


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)


class _Objects:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []
        self.refs: dict[str, ObjectRef] = {}
        self.material: dict[str, bytes] = {}
        self.abandoned: list[object] = []

    async def stage(self, source: ObjectSource, metadata: ObjectMetadata) -> ObjectMetadata:
        assert source.data is not None
        self.payloads.append(source.data)
        return metadata

    async def finalize(self, staged: ObjectMetadata) -> ObjectRef:
        payload = self.payloads[-1]
        object_id = PREFIX_BY_KIND[IdKind.OBJECT] + str(uuid.uuid4())
        ref = ObjectRef(
            object_id,
            len(payload),
            _COMMITMENT,
            _DIGEST,
            "yoetz-object/1",
            "slot1",
            staged,
        )
        self.refs[object_id] = ref
        self.material[object_id] = payload
        return ref

    async def abandon(self, staged: object) -> None:
        self.abandoned.append(staged)
        if not self.refs:
            return
        object_id = next(reversed(self.refs))
        del self.refs[object_id]
        del self.material[object_id]

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        ref = self.refs[object_id]
        assert ref.envelope_digest == envelope_digest
        return ref

    async def open_verified(self, ref: ObjectRef):
        yield self.material[ref.object_id]


def _coordinator(tmp_path: Path, objects: _Objects) -> ObservationCoordinator:
    return ObservationCoordinator(
        runtime=SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )


@pytest.mark.anyio
async def test_profile_rejection_fences_matching_pending_ticket(tmp_path: Path) -> None:
    envelope = ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind="PostToolUse",
        source_identity="hook:consent-profile",
        source=ObservationSource.CLAUDE_HOOK,
        cursor=ObservationCursor(1, 0, 1, _COMMITMENT, "claude-code-hooks-ordinary-v2"),
        receipt_time=Timestamp("2026-09-06T00:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell"}),
        content_object_refs=(),
        gap_codes=(),
    )
    ticket = ObservationCaptureTicket(
        workspace_commitment=_WORKSPACE,
        task_id=_TASK,
        finishup_session_id="ses_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        session_commitment=_COMMITMENT,
        source=ObservationSource.CLAUDE_HOOK,
        source_identity=envelope.source_identity,
        cursor=envelope.cursor,
        logical_identity=observation_content_identity(envelope),
        content_capture_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        authority_generation=_DIGEST,
        object_ids=("obj_00000000-0000-4000-8000-000000000001",),
        captured_at=Timestamp("2026-09-06T00:00:00.000Z"),
        state="pending",
        expected_parts=(
            (
                ObservationContentKind.TOOL_OUTPUT.value,
                envelope.source_identity,
                _COMMITMENT,
                0,
                1,
            ),
        ),
    )
    store = _ProfileMismatchStore(ticket)
    coordinator = ObservationCoordinator(
        runtime=SimpleNamespace(task_id=_TASK),  # type: ignore[arg-type]
        local=_NoAuthorityLocal(),  # type: ignore[arg-type]
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )
    request = ObservationIngestRequest(
        codex_session_id="claude:consent-profile",
        envelope=envelope,
        content_chunks=(),
        content_capture_profile=None,
    )

    context = await coordinator._native_capture_context(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        SimpleNamespace(task_id=_TASK, session_id=ticket.finishup_session_id),  # type: ignore[arg-type]
        store,  # type: ignore[arg-type]
        workspace=_WORKSPACE,
        request=request,
        consent=SimpleNamespace(content_capture_profiles=()),
    )

    assert context.rejection_reason == "content_capture_profile_mismatch"
    assert store.tombstones == [(_WORKSPACE, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)]


@pytest.mark.anyio
async def test_capture_fence_revoked_after_finalize_does_not_bind_manifest(
    tmp_path: Path,
) -> None:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": _TASK, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _Objects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind="PostToolUse",
        source_identity="hook:fence-finalize",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, _COMMITMENT, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-09-06T00:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell"}),
        content_object_refs=(),
        gap_codes=(),
    )
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        "call-fence-finalize",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"captured output",
    )
    revoked = False
    original_finalize = objects.finalize

    async def finalize_then_revoke(staged: ObjectMetadata) -> ObjectRef:
        nonlocal revoked
        ref = await original_finalize(staged)
        revoked = True
        return ref

    objects.finalize = finalize_then_revoke  # type: ignore[method-assign]

    async def fence() -> bool:
        return not revoked

    manifests, _replay, _redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(chunk,),
        capture_fence=fence,
    )

    assert revoked is True
    assert manifests == ()
    assert unavailable is True
    assert objects.abandoned
    assert objects.refs == {}
    assert db.execute("SELECT count(*) FROM observation_content_manifests").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM events").fetchone() == (0,)
