"""Abandon captured-content objects whose manifest row did not commit."""

from __future__ import annotations

import hashlib
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
from finishup.application.observation_verification import ObservationVerificationJob
from finishup.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.observability.diagnostics import lookup_diagnostic_records
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

_TASK = "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_COMMITMENT = "hmac-sha256:" + "c" * 64
_DIGEST = "sha256:" + "d" * 64
_WORKSPACE = "hmac-sha256:" + "1" * 64
_PLAINTEXT = b"captured output"


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)


class _Objects:
    def __init__(self) -> None:
        self.refs: dict[str, ObjectRef] = {}
        self.staged_payloads: dict[int, bytes] = {}
        self.abandoned: list[object] = []
        self.fail_abandon = False

    async def stage(self, source: ObjectSource, metadata: ObjectMetadata) -> ObjectMetadata:
        assert source.data is not None
        self.staged_payloads[id(metadata)] = source.data
        return metadata

    async def finalize(self, staged: ObjectMetadata) -> ObjectRef:
        payload = self.staged_payloads[id(staged)]
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
        return ref

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        ref = self.refs[object_id]
        assert ref.envelope_digest == envelope_digest
        return ref

    async def abandon(self, staged: object) -> None:
        if self.fail_abandon:
            raise OSError("captured output SECRET")
        self.abandoned.append(staged)
        owned = [object_id for object_id, ref in self.refs.items() if ref.metadata is staged]
        for object_id in owned:
            del self.refs[object_id]


class _FailingManifests(SqliteObservationStore):
    def __init__(self, connection: apsw.Connection, error: BaseException) -> None:
        super().__init__(connection)
        self.error = error
        self.attempts = 0

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
    ) -> None:
        del workspace, logical_identity, chunk, ref, content_digest, content_bytes, recorded_at
        self.attempts += 1
        raise self.error


class _UnknownManifestLookup(_FailingManifests):
    def content_manifest_object_id(
        self,
        *,
        workspace: str,
        logical_identity: str,
        chunk: ObservationContentChunk,
    ) -> str | None:
        if self.attempts:
            raise RuntimeError("manifest lookup unavailable")
        return super().content_manifest_object_id(
            workspace=workspace,
            logical_identity=logical_identity,
            chunk=chunk,
        )


def _coordinator(tmp_path: Path, objects: _Objects) -> ObservationCoordinator:
    return ObservationCoordinator(
        runtime=SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )


def _envelope(identity: str) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, _COMMITMENT, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-09-22T00:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell"}),
        content_object_refs=(),
        gap_codes=(),
    )


def _chunk(correlation: str) -> ObservationContentChunk:
    return ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        correlation,
        _COMMITMENT,
        "text/plain",
        0,
        1,
        _PLAINTEXT,
    )


def _bundle() -> tuple[apsw.Connection, SqliteObservationStore]:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": _TASK, "owner_generation": "1"})
    return db, SqliteObservationStore(db)


def _store_error(code: PublicErrorCode) -> PublicOperationError:
    return PublicOperationError(
        code, "Observation content manifest was not recorded.", retryable=False
    )


def _request_id(coordinator: ObservationCoordinator, object_id: str) -> str:
    return coordinator._captured_abandon_request_id(object_id)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_manifest_failure_abandons_finalized_object_and_keeps_the_ledger(
    tmp_path: Path,
) -> None:
    db, _store = _bundle()
    store = _FailingManifests(db, _store_error(PublicErrorCode.STORAGE_CORRUPT))
    objects = _Objects()
    coordinator = _coordinator(tmp_path, objects)

    with pytest.raises(PublicOperationError) as raised:
        await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
            store,
            workspace=_WORKSPACE,
            envelope=_envelope("hook:abandon-failure"),
            chunks=(_chunk("call-abandon"),),
        )

    assert raised.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert store.attempts == 1
    assert objects.abandoned
    assert objects.refs == {}
    assert db.execute("SELECT count(*) FROM observation_content_manifests").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM objects").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM events").fetchone() == (0,)


@pytest.mark.anyio
async def test_budget_fence_abandons_the_unowned_object_without_raising(tmp_path: Path) -> None:
    db, _store = _bundle()
    store = _FailingManifests(db, _store_error(PublicErrorCode.LIMIT_EXCEEDED))
    objects = _Objects()
    coordinator = _coordinator(tmp_path, objects)

    manifests, _replay, _redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=_envelope("hook:budget"),
        chunks=(_chunk("call-budget"),),
    )

    assert manifests == ()
    assert unavailable is True
    assert coordinator._capture_budget_exhausted is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert objects.refs == {}
    assert db.execute("SELECT count(*) FROM observation_content_manifests").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM events").fetchone() == (0,)


@pytest.mark.anyio
async def test_abandon_failure_is_logged_and_does_not_hide_the_store_error(
    tmp_path: Path,
) -> None:
    db, _store = _bundle()
    store = _FailingManifests(db, _store_error(PublicErrorCode.STORAGE_CORRUPT))
    objects = _Objects()
    objects.fail_abandon = True
    coordinator = _coordinator(tmp_path, objects)

    with pytest.raises(PublicOperationError) as raised:
        await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
            store,
            workspace=_WORKSPACE,
            envelope=_envelope("hook:abandon-log"),
            chunks=(_chunk("call-log"),),
        )

    assert raised.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert len(objects.refs) == 1
    (object_id,) = objects.refs
    records = lookup_diagnostic_records(request_id=_request_id(coordinator, object_id))
    assert records
    assert records[-1]["operation"] == "observation_object_abandon_failed"
    content_request_id = coordinator._stable_operation_id(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "sha256:" + hashlib.sha256(_PLAINTEXT).hexdigest()
    )
    assert not lookup_diagnostic_records(request_id=content_request_id)
    rendered = str(records)
    assert "SECRET" not in rendered
    assert "captured output" not in rendered


@pytest.mark.anyio
async def test_committed_manifest_is_not_deleted(tmp_path: Path) -> None:
    db, store = _bundle()
    objects = _Objects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _envelope("hook:committed")
    chunk = _chunk("call-committed")

    manifests, _replay, _redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(chunk,),
    )

    assert unavailable is False
    assert len(manifests) == 1
    assert objects.abandoned == []
    assert manifests[0].object_id in objects.refs
    named = store.content_manifest_object_id(
        workspace=_WORKSPACE,
        logical_identity=observation_content_identity(envelope),
        chunk=chunk,
    )
    assert named == manifests[0].object_id
    assert db.execute("SELECT count(*) FROM events").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM objects").fetchone() == (1,)


@pytest.mark.anyio
async def test_preexisting_manifest_owner_is_not_abandoned(tmp_path: Path) -> None:
    db, _store = _bundle()
    objects = _Objects()
    envelope = _envelope("hook:owned")
    chunk = _chunk("call-owned")
    object_id = PREFIX_BY_KIND[IdKind.OBJECT] + str(uuid.uuid4())
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT,
        "application/vnd.yoetz.observation-content+json",
        _TASK,
        datetime(2026, 1, 1, tzinfo=UTC),
    )
    ref = ObjectRef(object_id, 4, _COMMITMENT, _DIGEST, "yoetz-object/1", "slot1", metadata)
    objects.refs[object_id] = ref
    db.execute(
        "INSERT INTO objects(object_id,kind,plaintext_size,commitment,envelope_digest,"
        "encryption_format,key_slot,state,durable_at) VALUES(?,?,?,?,?,?,?,'present',?)",
        (
            object_id,
            "captured_content",
            4,
            _COMMITMENT,
            _DIGEST,
            "yoetz-object/1",
            "slot1",
            "2026-09-22T00:00:00.000Z",
        ),
    )
    db.execute(
        "INSERT INTO observation_content_manifests("
        "object_id,workspace_commitment,logical_identity,content_kind,correlation_identity,"
        "source_commitment,media_type,part_index,part_count,plaintext_size,content_commitment,"
        "redacted,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            object_id,
            _WORKSPACE,
            observation_content_identity(envelope),
            chunk.content_kind.value,
            chunk.correlation_identity,
            chunk.source_commitment,
            chunk.media_type,
            chunk.part_index,
            chunk.part_count,
            4,
            _COMMITMENT,
            0,
            "2026-09-22T00:00:00.000Z",
        ),
    )
    failing = _FailingManifests(db, _store_error(PublicErrorCode.STORAGE_CORRUPT))
    coordinator = _coordinator(tmp_path, objects)

    with pytest.raises(PublicOperationError):
        await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
            failing,
            workspace=_WORKSPACE,
            envelope=envelope,
            chunks=(chunk,),
            allow_incomplete_recovery=True,
        )

    assert objects.abandoned == []
    assert object_id in objects.refs
    assert db.execute("SELECT object_id FROM observation_content_manifests").fetchone() == (
        object_id,
    )
    assert db.execute("SELECT count(*) FROM events").fetchone() == (0,)


@pytest.mark.anyio
async def test_unknown_manifest_lookup_does_not_abandon(tmp_path: Path) -> None:
    db, _store = _bundle()
    store = _UnknownManifestLookup(db, _store_error(PublicErrorCode.STORAGE_CORRUPT))
    objects = _Objects()
    coordinator = _coordinator(tmp_path, objects)

    with pytest.raises(PublicOperationError) as raised:
        await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
            store,
            workspace=_WORKSPACE,
            envelope=_envelope("hook:unknown-lookup"),
            chunks=(_chunk("call-unknown"),),
        )

    assert raised.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert objects.abandoned == []
    assert objects.refs


@pytest.mark.anyio
async def test_approved_check_manifest_failure_abandons_and_success_keeps_the_object(
    tmp_path: Path,
) -> None:
    db, store = _bundle()
    objects = _Objects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    job = ObservationVerificationJob(
        job_id="job_abandon",
        workspace_commitment=_WORKSPACE,
        policy_digest=_DIGEST,
        approval_commitment=_DIGEST,
        subject_state_digest=_DIGEST,
        state_token=1,
    )
    failing = _FailingManifests(db, _store_error(PublicErrorCode.STORAGE_CORRUPT))

    with pytest.raises(PublicOperationError):
        await coordinator._persist_approved_check_output(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            runtime,  # type: ignore[arg-type]
            failing,
            _WORKSPACE,
            job,
            b"ordinary check output",
        )

    assert objects.refs == {}
    assert db.execute("SELECT count(*) FROM observation_content_manifests").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM events").fetchone() == (0,)

    object_id = await coordinator._persist_approved_check_output(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        _WORKSPACE,
        job,
        b"ordinary check output",
    )

    assert object_id is not None
    assert object_id in objects.refs
    assert db.execute("SELECT object_id FROM observation_content_manifests").fetchone() == (
        object_id,
    )
    assert db.execute("SELECT count(*) FROM events").fetchone() == (0,)
