"""Changed-file excerpts and approved-check output share the fail-closed scanner."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import apsw
import pytest

from yoetz.adapters.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckCommand,
    ApprovedCheckRunner,
    approval_commitment,
)
from yoetz.adapters.integrations.codex_lifecycle import LifecycleMapping
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.adapters.sqlite.migrations import initialize_bundle
from yoetz.adapters.sqlite.observation import SqliteObservationStore
from yoetz.adapters.workspace_inspect import open_inspect_workspace
from yoetz.application.observation_coordinator import (
    ObservationCoordinator,
    build_inspection_excerpt_manifest,
)
from yoetz.application.observation_materialize import (
    MATERIALIZATION_MAPPING_VERSION,
    MaterializedObservationBatch,
    canonical_logical_identity,
    materialize_observation_envelope,
    observation_operation_digest,
    observation_writer_id,
)
from yoetz.application.observation_verification import ObservationVerificationJob
from yoetz.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.domain.values import JsonObject, Timestamp
from yoetz.observability.privacy import PersistenceScanResult
from yoetz.ports.check_sandbox import CheckSandboxLaunch, CheckSandboxStatus
from yoetz.ports.objects import ObjectMetadata, ObjectRef, ObjectSource
from yoetz.ports.workspace_inspect import InspectedArtifact
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.ids import PREFIX_BY_KIND, IdKind

_TASK = "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_DIGEST = "sha256:" + "ab" * 32
_COMMITMENT = "hmac-sha256:" + "cd" * 32
_WORKSPACE = "hmac-sha256:" + "11" * 32
_SECRET = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_AZURE = b"AZURE_CLIENT_SECRET=abc123secretvalue0001"
_TOKEN = b"GITHUB_TOKEN=notakeybutlongenoughvalue"
# A high-confidence credential shape. The three assignments above are heuristic-only: capture keeps
# them in the encrypted store and egress redacts them (issue #982).
_HIGH_VALUE = b"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
_HIGH_SECRET = b"OPENAI_API_KEY=" + _HIGH_VALUE


class _ReadySandbox:
    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        del deny_network
        return CheckSandboxLaunch(
            argv=tuple(argv),
            env=dict(env),
            cwd=cwd,
            status=CheckSandboxStatus.READY,
            network_isolated=True,
        )


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC)


class _CapturingObjects:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []
        self.refs: dict[str, ObjectRef] = {}
        self.object_payloads: dict[str, bytes] = {}

    async def stage(self, source: ObjectSource, metadata: ObjectMetadata) -> ObjectMetadata:
        assert source.data is not None
        self.payloads.append(source.data)
        return metadata

    async def finalize(self, staged: ObjectMetadata) -> ObjectRef:
        payload = self.payloads[-1]
        ref = ObjectRef(
            PREFIX_BY_KIND[IdKind.OBJECT] + str(uuid.uuid4()),
            len(payload),
            _COMMITMENT,
            _DIGEST,
            "yoetz-object/1",
            "slot1",
            staged,
        )
        self.refs[ref.object_id] = ref
        self.object_payloads[ref.object_id] = payload
        return ref

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        ref = self.refs[object_id]
        assert ref.envelope_digest == envelope_digest
        return ref

    async def open_verified(self, ref: ObjectRef):
        yield self.object_payloads[ref.object_id]


def _artifact(relative_path: str, excerpt: bytes) -> InspectedArtifact:
    digest = "sha256:" + hashlib.sha256(excerpt).hexdigest()
    return InspectedArtifact(relative_path, digest, excerpt, False, len(excerpt))


def _job() -> ObservationVerificationJob:
    return ObservationVerificationJob(
        job_id="job_1",
        workspace_commitment=_WORKSPACE,
        policy_digest=_DIGEST,
        approval_commitment=_DIGEST,
        subject_state_digest=_DIGEST,
        state_token=1,
    )


def _coordinator(tmp_path: Path, objects: _CapturingObjects) -> ObservationCoordinator:
    return ObservationCoordinator(
        runtime=SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )


def _observation_envelope(*, refs: tuple[str, ...] = ()) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind="PostToolUse",
        source_identity="hook:issue-302",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, _COMMITMENT, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-08-30T00:00:00.000Z"),
        structural_payload=JsonObject({"correlation_id": "call-302", "tool_name": "shell"}),
        content_object_refs=refs,
        gap_codes=(),
    )


@pytest.mark.anyio
async def test_observation_capture_binds_inner_bytes_and_deleted_object_weakens(
    tmp_path: Path,
) -> None:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    content = b"captured command output\n"
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        "call-302",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        content,
    )

    manifests, replay, redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(chunk,),
    )
    assert redacted is False
    assert unavailable is False
    assert replay == ()
    assert len(manifests) == 1
    assert manifests[0].content_digest == "sha256:" + hashlib.sha256(content).hexdigest()
    assert manifests[0].content_bytes == len(content)

    recovered, replay, redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )
    assert recovered == manifests
    assert replay == (manifests,)
    assert redacted is False
    assert unavailable is False

    db.execute(
        "UPDATE observation_content_manifests SET content_digest=? WHERE object_id=?",
        ("sha256:" + "f" * 64, manifests[0].object_id),
    )
    rebound, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )
    assert rebound == ()
    assert manifests in replay
    assert unavailable is True
    db.execute(
        "UPDATE observation_content_manifests SET content_digest=? WHERE object_id=?",
        (manifests[0].content_digest, manifests[0].object_id),
    )

    objects.refs.pop(manifests[0].object_id)
    recovered, replay, redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=_observation_envelope(refs=(manifests[0].object_id,)),
        chunks=(),
    )
    assert recovered == ()
    assert replay == (manifests,)
    assert redacted is False
    assert unavailable is True
    weakened = materialize_observation_envelope(
        replace(
            _observation_envelope(refs=(manifests[0].object_id,)),
            gap_codes=("content_capture_unavailable",),
        ),
        task_id=_TASK,
        captured_content=recovered,
    )
    assert all(not item.role.startswith("captured_") for item in weakened.drafts)
    replay_only = materialize_observation_envelope(
        _observation_envelope(refs=(manifests[0].object_id,)),
        task_id=_TASK,
        captured_content=replay[0],
    )
    assert any(item.role.startswith("captured_") for item in replay_only.drafts)


@pytest.mark.anyio
async def test_capture_rejects_noncanonical_inner_media_without_staging(
    tmp_path: Path,
) -> None:
    """Native captured-content ingress only persists canonical ``text/plain`` chunks."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    invalid = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        "call-302",
        _COMMITMENT,
        "application/json",
        0,
        1,
        b'{"ok":true}',
    )

    manifests, replay, redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(invalid,),
    )

    assert manifests == ()
    assert replay == ()
    assert redacted is False
    assert unavailable is True
    assert objects.payloads == []

    valid = replace(invalid, media_type="text/plain", content=b"captured")
    manifests, _, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(valid,),
    )
    assert len(manifests) == 1
    assert unavailable is False
    wrapped = json.loads(objects.object_payloads[manifests[0].object_id])
    wrapped["media_type"] = "application/json"
    objects.object_payloads[manifests[0].object_id] = canonical_encode(wrapped)
    recovered, _, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )
    assert recovered == ()
    assert unavailable is True


@pytest.mark.anyio
async def test_same_phase_stream_copy_reuses_hook_manifest_roles(tmp_path: Path) -> None:
    """#539: equivalent sources share roles without expanding them after commit."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    hook = _observation_envelope()
    hook_chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        f"{hook.source_identity}:tool-output",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"hook output",
    )
    first, _, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=hook,
        chunks=(hook_chunk,),
    )
    assert unavailable is False

    stream = replace(
        hook,
        event_kind="item.completed",
        source=ObservationSource.CODEX_SESSION_STREAM,
        source_identity="stream:issue-539",
    )
    stream_chunk = replace(
        hook_chunk,
        correlation_identity=f"{stream.source_identity}:tool-output",
        content=b"equivalent stream output",
    )
    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=stream,
        chunks=(stream_chunk,),
    )

    assert usable == first
    assert replay == (first,)
    assert unavailable is True


@pytest.mark.anyio
async def test_legacy_hook_manifest_is_replay_candidate_for_stream_copy(tmp_path: Path) -> None:
    """#539: a post-upgrade stream copy can find a pre-upgrade hook commit."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    hook = _observation_envelope()
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        f"{hook.source_identity}:tool-output",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"legacy hook output",
    )
    first, _, _, _ = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=hook,
        chunks=(chunk,),
    )
    db.execute(
        "UPDATE observation_content_manifests SET logical_identity=?",
        (canonical_logical_identity(hook),),
    )
    stream = replace(
        hook,
        event_kind="item.completed",
        source=ObservationSource.CODEX_SESSION_STREAM,
        source_identity="stream:legacy-issue-539",
    )

    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=stream,
        chunks=(),
    )

    assert usable == ()
    assert first in replay
    assert unavailable is False


@pytest.mark.anyio
async def test_legacy_unbound_manifest_stays_replay_only_without_adding_role(
    tmp_path: Path,
) -> None:
    """#539: NULL legacy digest metadata preserves the original core-only roles."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        f"{envelope.source_identity}:tool-output",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"legacy unbound output",
    )
    first, _, _, _ = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(chunk,),
    )
    db.execute(
        "UPDATE observation_content_manifests "
        "SET logical_identity=?,content_digest=NULL,content_bytes=NULL",
        (canonical_logical_identity(envelope),),
    )

    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=replace(envelope, content_object_refs=(first[0].object_id,)),
        chunks=(),
    )

    assert usable == ()
    assert unavailable is True
    assert any(candidate[0].content_digest is None for candidate in replay)
    core = materialize_observation_envelope(envelope, task_id=_TASK, captured_content=usable)
    legacy = materialize_observation_envelope(
        replace(envelope, content_object_refs=(first[0].object_id,)),
        task_id=_TASK,
        captured_content=next(item for item in replay if item[0].content_digest is None),
    )
    assert tuple(item.role for item in legacy.drafts) == tuple(item.role for item in core.drafts)


@pytest.mark.anyio
async def test_incomplete_manifest_parts_weaken_new_materialization(tmp_path: Path) -> None:
    """#539: a partial manifest set is a gap, never partial captured coverage."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    chunks = tuple(
        ObservationContentChunk(
            ObservationContentKind.TOOL_OUTPUT,
            f"{envelope.source_identity}:tool-output",
            _COMMITMENT,
            "text/plain",
            index,
            2,
            f"part-{index}".encode(),
        )
        for index in range(2)
    )
    first, _, _, _ = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=chunks,
    )
    db.execute(
        "DELETE FROM observation_content_manifests WHERE object_id=?",
        (first[1].object_id,),
    )

    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )

    assert usable == ()
    assert replay
    assert unavailable is True


@pytest.mark.anyio
async def test_initial_partial_multipart_capture_never_becomes_evidence(tmp_path: Path) -> None:
    """#539: a partial first delivery is persisted but cannot earn coverage."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    partial = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        f"{envelope.source_identity}:tool-output",
        _COMMITMENT,
        "text/plain",
        0,
        2,
        b"part-0",
    )

    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(partial,),
    )

    assert usable == ()
    assert replay == ()
    assert unavailable is True
    batch = materialize_observation_envelope(envelope, task_id=_TASK, captured_content=usable)
    assert all(not item.role.startswith("captured_") for item in batch.drafts)


@pytest.mark.anyio
async def test_unreadable_multipart_object_weaken_all_parts(tmp_path: Path) -> None:
    """#539: one unreadable object cannot leave partial captured coverage."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    chunks = tuple(
        ObservationContentChunk(
            ObservationContentKind.TOOL_OUTPUT,
            f"{envelope.source_identity}:tool-output",
            _COMMITMENT,
            "text/plain",
            index,
            2,
            f"part-{index}".encode(),
        )
        for index in range(2)
    )
    first, _, _, _ = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=chunks,
    )
    objects.refs.pop(first[1].object_id)

    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )

    assert usable == ()
    assert replay
    assert unavailable is True


@pytest.mark.anyio
async def test_conflicting_multipart_source_commitments_weaken_new_materialization(
    tmp_path: Path,
) -> None:
    """#539: contradictory multipart metadata cannot grant captured coverage."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    chunks = tuple(
        ObservationContentChunk(
            ObservationContentKind.TOOL_OUTPUT,
            f"{envelope.source_identity}:tool-output",
            _COMMITMENT,
            "text/plain",
            index,
            2,
            f"part-{index}".encode(),
        )
        for index in range(2)
    )
    first, _, _, _ = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=chunks,
    )
    db.execute(
        "UPDATE observation_content_manifests SET source_commitment=? WHERE object_id=?",
        (f"hmac-sha256:{'ef' * 32}", first[1].object_id),
    )

    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )

    assert usable == ()
    assert replay
    assert unavailable is True


@pytest.mark.anyio
async def test_missing_object_inventory_is_content_gap_not_session_corruption(
    tmp_path: Path,
) -> None:
    """#539: an orphaned manifest remains lookup-only and does not latch storage."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    envelope = _observation_envelope()
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        f"{envelope.source_identity}:tool-output",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"orphaned inventory output",
    )
    first, _, _, _ = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(chunk,),
    )
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute("DELETE FROM objects WHERE object_id=?", (first[0].object_id,))
    db.execute("PRAGMA foreign_keys=ON")

    usable, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )

    assert usable == ()
    assert replay
    assert replay[0][0].envelope_digest is None
    assert unavailable is True


@pytest.mark.anyio
async def test_legacy_manifest_recovery_does_not_borrow_sibling_phase_content(
    tmp_path: Path,
) -> None:
    """#539: legacy sibling content is lookup-only, never usable evidence."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    post = replace(
        _observation_envelope(),
        source_identity="hook:post-539",
        structural_payload=JsonObject(
            {
                "correlation_id": "call-539",
                "tool_call_id": "call-539",
                "tool_name": "shell",
                "exit_status": 0,
            }
        ),
    )
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        f"{post.source_identity}:tool-output",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"post-only output",
    )
    captured, _, _, _ = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=post,
        chunks=(chunk,),
    )
    assert captured
    db.execute(
        "UPDATE observation_content_manifests SET logical_identity=?",
        (canonical_logical_identity(post),),
    )
    pre = replace(
        post,
        event_kind="PreToolUse",
        source_identity="hook:pre-539",
        structural_payload=JsonObject(
            {
                "correlation_id": "call-539",
                "tool_call_id": "call-539",
                "tool_name": "shell",
            }
        ),
    )
    assert canonical_logical_identity(pre) == canonical_logical_identity(post)

    recovered, replay, _, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=replace(pre, content_object_refs=(captured[0].object_id,)),
        chunks=(),
    )

    assert recovered == ()
    assert captured in replay
    assert unavailable is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("kind", "content_kind", "gaps", "exit_status"),
    [
        ("PostToolUse", ObservationContentKind.TOOL_OUTPUT, (), 0),
        (
            "PostToolUse",
            ObservationContentKind.TOOL_OUTPUT,
            ("unpaired_event",),
            0,
        ),
        ("PreToolUse", ObservationContentKind.TOOL_INPUT, (), None),
    ],
)
async def test_contentless_retry_reconstructs_committed_materialization_identity(
    tmp_path: Path,
    kind: str,
    content_kind: ObservationContentKind,
    gaps: tuple[str, ...],
    exit_status: int | None,
) -> None:
    """#539: persisted manifests restore the exact content-bearing role set."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    structural: dict[str, object] = {
        "correlation_id": "call-539",
        "tool_call_id": "call-539",
        "tool_name": "shell",
    }
    if exit_status is not None:
        structural["exit_status"] = exit_status
    envelope = ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind=kind,
        source_identity="hook:issue-539",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, _COMMITMENT, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-09-03T00:00:00.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=gaps,
    )
    chunk = ObservationContentChunk(
        content_kind,
        f"{envelope.source_identity}:captured",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"content that exists only on the originating hook pass",
    )

    first, first_replay, _, first_unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(chunk,),
    )
    # Simulate a manifest written by the pre-#539 runtime, which keyed content
    # on the cross-phase canonical action identity.
    db.execute(
        "UPDATE observation_content_manifests SET logical_identity=?",
        (canonical_logical_identity(envelope),),
    )
    replayed, replay_candidates, _, replay_unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=envelope,
        chunks=(),
    )
    assert replayed == first
    assert first_replay == ()
    assert replay_candidates == (first,)
    assert first_unavailable is replay_unavailable is False

    first_envelope = replace(
        envelope,
        content_object_refs=tuple(item.object_id for item in first),
    )
    replay_envelope = replace(
        envelope,
        content_object_refs=tuple(item.object_id for item in replayed),
    )
    first_batch = materialize_observation_envelope(
        first_envelope, task_id=_TASK, captured_content=first
    )
    replay_batch = materialize_observation_envelope(
        replay_envelope, task_id=_TASK, captured_content=replayed
    )
    first_roles = tuple(item.role for item in first_batch.drafts)
    replay_roles = tuple(item.role for item in replay_batch.drafts)
    assert replay_roles == first_roles
    identity = canonical_logical_identity(envelope)
    first_digest = observation_operation_digest(
        task_id=_TASK,
        logical_identity=identity,
        draft_roles=first_roles,
    )
    replay_digest = observation_operation_digest(
        task_id=_TASK,
        logical_identity=identity,
        draft_roles=replay_roles,
    )
    assert replay_digest == first_digest


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("kind", "content_kind", "gaps", "exit_status", "core_roles"),
    [
        (
            "PostToolUse",
            ObservationContentKind.TOOL_OUTPUT,
            (),
            0,
            ("action", "result"),
        ),
        (
            "PostToolUse",
            ObservationContentKind.TOOL_OUTPUT,
            ("unpaired_event",),
            0,
            ("unpaired_evidence",),
        ),
        (
            "PreToolUse",
            ObservationContentKind.TOOL_INPUT,
            (),
            None,
            ("action",),
        ),
    ],
)
@pytest.mark.parametrize("content_first", [True, False], ids=["content-first", "content-late"])
async def test_coordinator_replays_content_commit_after_reply_is_lost(
    tmp_path: Path,
    kind: str,
    content_kind: ObservationContentKind,
    gaps: tuple[str, ...],
    exit_status: int | None,
    core_roles: tuple[str, ...],
    content_first: bool,
) -> None:
    """#539: either content arrival order reuses the first immutable operation."""

    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    codex_session_id = f"reply-lost-{kind}-{len(gaps)}"
    session_commitment = local.bind_codex_session(workspace, codex_session_id)
    task_id = _TASK
    yoetz_session_id = "ses_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    writer_id = observation_writer_id(task_id, yoetz_session_id)
    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=codex_session_id,
        yoetz_task_id=task_id,
        yoetz_session_id=yoetz_session_id,
        yoetz_writer_id=writer_id,
        last_frontier=None,
    )
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": task_id, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    runtime = SimpleNamespace(
        task_id=task_id,
        session_id=yoetz_session_id,
        writer_id=writer_id,
        observation=store,
        objects=objects,
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            assert released is runtime

    class _ReplayCoordinator(ObservationCoordinator):
        committed_roles: tuple[str, ...] | None = None
        operation_ids: list[str] = []
        outcomes: list[str] = []
        batches: list[MaterializedObservationBatch] = []

        async def _append_materialized(  # type: ignore[override]
            self,
            runtime: object,
            envelope: ObservationEnvelope,
            batch: MaterializedObservationBatch,
            *,
            captured_content: tuple[object, ...] = (),
            legacy_session_id: str | None = None,
            legacy_writer_id: str | None = None,
            legacy_writer_routes: tuple[tuple[str, str], ...] = (),
            replay_required: bool = False,
            replay_claims: tuple[tuple[tuple[str, str, str], tuple[str, ...]], ...] = (),
            replay_draft_role_sets: tuple[tuple[str, ...], ...] = (),
        ) -> tuple[str, str, None, str, tuple[str, ...]]:
            del (
                captured_content,
                legacy_session_id,
                legacy_writer_id,
                legacy_writer_routes,
                replay_required,
                replay_claims,
            )
            self.batches.append(batch)
            current_roles = tuple(item.role for item in batch.drafts)
            candidates = (current_roles, *replay_draft_role_sets)
            if self.committed_roles is None:
                self.committed_roles = current_roles
                self.outcomes.append("accepted")
            elif self.committed_roles in candidates:
                self.outcomes.append("replayed")
            else:
                raise AssertionError("content-less retry missed the committed role set")
            digest = observation_operation_digest(
                task_id=runtime.task_id,  # type: ignore[attr-defined]
                logical_identity=canonical_logical_identity(envelope),
                draft_roles=self.committed_roles,
            )
            operation_id = self._stable_operation_id(digest)
            self.operation_ids.append(operation_id)
            return (
                operation_id,
                digest,
                None,
                MATERIALIZATION_MAPPING_VERSION,
                self.committed_roles,
            )

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    coordinator = _ReplayCoordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    structural: dict[str, object] = {
        "correlation_id": "call-539",
        "tool_call_id": "call-539",
        "tool_name": "shell",
    }
    if exit_status is not None:
        structural["exit_status"] = exit_status
    envelope = ObservationEnvelope(
        session_commitment=session_commitment,
        event_kind=kind,
        source_identity=f"hook:reply-lost:{kind}:{len(gaps)}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            1,
            0,
            1,
            session_commitment,
            "codex-obs-hook/1.0.0",
        ),
        receipt_time=Timestamp("2026-09-03T00:00:00.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=gaps,
    )
    chunk = ObservationContentChunk(
        content_kind,
        f"{envelope.source_identity}:captured",
        session_commitment,
        "text/plain",
        0,
        1,
        b"captured only on the first delivery",
    )

    first = await coordinator.ingest_request(
        ObservationIngestRequest(codex_session_id, envelope, (chunk,) if content_first else ())
    )
    # The caller intentionally ignores the first reply, modeling a client-side
    # timeout after the service-side commit. Exercise both the durable
    # contentless retry and the inverse late-content equivalent copy.
    replayed = await coordinator.ingest_request(
        ObservationIngestRequest(codex_session_id, envelope, () if content_first else (chunk,))
    )

    assert first.disposition is ObservationIngestDisposition.ACCEPTED
    assert replayed.disposition is ObservationIngestDisposition.DUPLICATE
    assert coordinator.outcomes == ["accepted", "replayed"]
    assert len(set(coordinator.operation_ids)) == 1
    assert coordinator.committed_roles is not None
    assert all(role in coordinator.committed_roles for role in core_roles)
    has_captured_role = any(
        role.startswith(f"captured_{content_kind.value}") for role in coordinator.committed_roles
    )
    if content_kind is ObservationContentKind.TOOL_INPUT:
        assert has_captured_role is False
        selected_batch = coordinator.batches[0 if content_first else 1]
        assert "content_unselected" in selected_batch.gaps
    elif not content_first:
        assert has_captured_role is False
    else:
        assert has_captured_role is True
    if not content_first and content_kind is ObservationContentKind.TOOL_OUTPUT:
        assert any(
            role.startswith("captured_")
            for role in (item.role for item in coordinator.batches[1].drafts)
        )
        status = local.status(ObservationStatusQuery(workspace))
        assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in status.gaps


@pytest.mark.anyio
async def test_observation_capture_secret_scans_before_digest_binding(tmp_path: Path) -> None:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        "call-302",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        b"prefix " + _HIGH_SECRET + b"\n" + _SECRET,
    )

    manifests, replay, redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=_observation_envelope(),
        chunks=(chunk,),
    )
    assert redacted is True
    assert unavailable is False
    assert replay == ()
    assert len(manifests) == 1
    captured_envelope = objects.payloads[0]
    assert _HIGH_VALUE not in captured_envelope
    captured_inner = base64.b64decode(json.loads(captured_envelope)["content_b64"])
    assert _HIGH_VALUE not in captured_inner
    # The heuristic-only assignment stays as captured in the encrypted object (issue #982).
    assert _SECRET in captured_inner
    assert manifests[0].redacted is True
    assert manifests[0].content_digest == ("sha256:" + hashlib.sha256(captured_inner).hexdigest())


@pytest.mark.anyio
async def test_observation_capture_keeps_heuristic_only_content_unredacted(tmp_path: Path) -> None:
    """Issue #982: a heuristic-only match neither changes bytes nor marks the chunk redacted."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    runtime = SimpleNamespace(task_id=_TASK, objects=objects)
    content = b'        self.bot_token = "<|tool_call_start|>"\n' + _TOKEN + b"\n"
    chunk = ObservationContentChunk(
        ObservationContentKind.TOOL_OUTPUT,
        "call-303",
        _COMMITMENT,
        "text/plain",
        0,
        1,
        content,
    )

    manifests, _replay, redacted, unavailable = await coordinator._capture_content(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        runtime,  # type: ignore[arg-type]
        store,
        workspace=_WORKSPACE,
        envelope=_observation_envelope(),
        chunks=(chunk,),
    )
    assert redacted is False
    assert unavailable is False
    assert len(manifests) == 1
    assert manifests[0].redacted is False
    parsed = json.loads(objects.payloads[0])
    assert parsed["redacted"] is False
    assert base64.b64decode(parsed["content_b64"]) == content


def test_changed_file_prefix_canary_persists_only_redaction_metadata() -> None:
    secret_file = _artifact("src/env.py", b"export " + _HIGH_SECRET + b"\nprint(1)\n")
    clean_file = _artifact("src/ok.py", b"print('hello-advice')\n")
    encoded, unavailable, redacted, truncated = build_inspection_excerpt_manifest(
        (secret_file, clean_file)
    )
    assert unavailable is False
    assert redacted is True
    assert truncated is False
    assert encoded is not None
    parsed = json.loads(encoded)
    artifacts = parsed["artifacts"]
    assert artifacts[0]["path"] == "src/env.py"
    assert artifacts[0]["redacted"] is True
    assert artifacts[0]["finding_kinds"] == ["credential_pattern"]
    assert "excerpt_b64" not in artifacts[0]
    assert artifacts[1]["redacted"] is False
    recovered = base64.b64decode(artifacts[1]["excerpt_b64"])
    assert b"hello-advice" in recovered
    assert _HIGH_SECRET not in encoded
    assert _HIGH_VALUE not in encoded


def test_changed_file_canary_withholds_excerpt_object() -> None:
    canary = b"unique-inspect-canary-\x00-secret"
    encoded, unavailable, redacted, truncated = build_inspection_excerpt_manifest(
        (_artifact("notes.txt", b"prefix " + canary),),
        canaries=(canary,),
    )
    assert encoded is None
    assert unavailable is True
    assert redacted is False
    assert truncated is False


def test_changed_file_scanner_failure_stores_no_excerpt(monkeypatch: pytest.MonkeyPatch) -> None:
    def _withhold(data: bytes, *, canaries: tuple[bytes, ...] = ()) -> PersistenceScanResult:
        del data, canaries
        return PersistenceScanResult(False, b"", True, ())

    monkeypatch.setattr(
        "yoetz.application.observation_coordinator.prepare_persisted_plaintext",
        _withhold,
    )
    encoded, unavailable, redacted, truncated = build_inspection_excerpt_manifest(
        (_artifact("notes.txt", b"ordinary excerpt bytes"),)
    )
    assert encoded is None
    assert unavailable is True
    assert redacted is False
    assert truncated is False


def test_azure_and_token_prefixes_are_kept_in_the_encrypted_excerpt() -> None:
    """Issue #982: heuristic-only assignments are local evidence; egress redacts them."""

    encoded, unavailable, redacted, truncated = build_inspection_excerpt_manifest(
        (_artifact("a.env", _AZURE + b"\n"), _artifact("b.env", _TOKEN + b"\n"))
    )
    assert unavailable is False
    assert redacted is False
    assert truncated is False
    assert encoded is not None
    parsed = json.loads(encoded)
    excerpts = [base64.b64decode(item["excerpt_b64"]) for item in parsed["artifacts"]]
    assert all(item["redacted"] is False for item in parsed["artifacts"])
    assert excerpts == [_AZURE + b"\n", _TOKEN + b"\n"]


@pytest.mark.anyio
async def test_approved_check_persistence_path_redacts_compound_secrets(
    tmp_path: Path,
) -> None:
    handle = open_inspect_workspace(tmp_path)
    captured: list[bytes] = []
    argv = ("/bin/echo", _HIGH_SECRET.decode("ascii"), _SECRET.decode("ascii"))
    approval = ApprovedCheckApproval(
        approval_id="pytest-unit",
        argv=argv,
        allow_network=False,
        timeout_seconds=10.0,
        approval_commitment=approval_commitment("pytest-unit", argv, allow_network=False),
    )
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadySandbox(),
        output_sink=captured.append,
    )
    runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest=_DIGEST,
        )
    )
    assert captured
    assert _HIGH_VALUE not in captured[0]
    assert b"[REDACTED]" in captured[0]
    # Heuristic-only output stays in the encrypted object; egress redacts it (issue #982).
    assert b"wJalrXUtnFEMI" in captured[0]

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    object_id = await coordinator._persist_approved_check_output(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
        store,
        _WORKSPACE,
        _job(),
        # The runner's own replacement is not reported through the output sink, so the
        # coordinator's persisted ``redacted`` flag reflects only the bytes it replaces itself.
        captured[0] + b"\n" + _AZURE + b"\n" + _HIGH_SECRET,
    )
    assert object_id is not None
    assert objects.payloads
    payload = objects.payloads[0]
    assert _HIGH_VALUE not in payload
    parsed = json.loads(payload)
    decoded = base64.b64decode(parsed["content_b64"])
    assert b"[REDACTED]" in decoded
    assert b"abc123secretvalue0001" in decoded
    assert parsed["redacted"] is True
    rows = db.execute(
        "SELECT redacted,content_kind,content_digest,content_bytes "
        "FROM observation_content_manifests"
    ).fetchall()
    assert rows == [
        (
            1,
            "approved_check_output",
            "sha256:" + hashlib.sha256(decoded).hexdigest(),
            len(decoded),
        )
    ]


@pytest.mark.anyio
async def test_approved_check_persistence_withholds_when_scan_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _withhold(data: bytes, *, canaries: tuple[bytes, ...] = ()) -> PersistenceScanResult:
        del data, canaries
        return PersistenceScanResult(False, b"", True, ("canary",))

    monkeypatch.setattr(
        "yoetz.application.observation_coordinator.prepare_persisted_plaintext",
        _withhold,
    )
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    objects = _CapturingObjects()
    coordinator = _coordinator(tmp_path, objects)
    object_id = await coordinator._persist_approved_check_output(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        SimpleNamespace(task_id=_TASK, objects=objects),  # type: ignore[arg-type]
        store,
        _WORKSPACE,
        _job(),
        b"AWS_SECRET_ACCESS_KEY=should-not-be-stored",
    )
    assert object_id is None
    assert objects.payloads == []
    assert db.execute("SELECT COUNT(*) FROM observation_content_manifests").fetchone() == (0,)
