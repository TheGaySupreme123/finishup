"""Runtime lease cleanup around observation ingest finalizers."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import apsw  # pyright: ignore[reportMissingImports]
import pytest

from builders.ledger_adapters import FixedClock, FixedIds
from finishup.adapters.integrations.codex_lifecycle import LifecycleMapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.sqlite.migrations import (
    initialize_bundle,  # pyright: ignore[reportUnknownVariableType]
)
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.application import observation_coordinator as coordinator_module
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.application.observation_materialize import (
    MATERIALIZATION_MAPPING_VERSION,
    observation_writer_id,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


def _id(kind: IdKind) -> str:
    return PREFIX_BY_KIND[kind] + str(uuid.uuid4())


@dataclass
class _RuntimePort:
    runtime: object
    releases: int = 0

    async def route(self, command: object) -> object:
        del command
        return self.runtime

    async def release(self, runtime: object) -> None:
        assert runtime is self.runtime
        self.releases += 1


class _ProbeCoordinator(ObservationCoordinator):
    def __init__(self, *, publish_mode: str, **kwargs: object) -> None:
        super().__init__(**cast(Any, kwargs))
        self.publish_mode = publish_mode
        self.publish_entered = asyncio.Event()

    async def _native_capture_context(self, *args: object, **kwargs: object) -> object:  # type: ignore[override]
        del args, kwargs
        return coordinator_module._NativeCaptureContext(  # pyright: ignore[reportPrivateUsage]
            native_source=False,
            requested_content_profile=None,
            content_identity=None,
            pending_capture_ticket=None,
            content_authorized=False,
            content_authorization_missing=False,
            content_capture_blocked=True,
            capture_ticket_revoked=False,
            native_content_requested=False,
            capture_fence=None,
            fence_generation=None,
            capture_staging_ticket=None,
            staged_ticket=None,
            expected_capture_parts=None,
            rejection_reason=None,
        )

    async def _append_materialized(self, *args: object, **kwargs: object) -> tuple[object, ...]:  # type: ignore[override]
        del kwargs
        batch = cast(Any, args[2])
        roles = tuple(item.role for item in batch.drafts)
        digest = canonical_digest({"runtime_release_test": roles})
        return (
            _id(IdKind.REQUEST),
            digest,
            None,
            MATERIALIZATION_MAPPING_VERSION,
            roles,
        )

    async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        del args, kwargs

    async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        del args, kwargs

    async def _sweep_lineage(self, task_id: str) -> None:  # type: ignore[override]
        del task_id

    async def _publish_capture_backlog(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        del args, kwargs
        self.publish_entered.set()
        if self.publish_mode == "raise":
            raise RuntimeError("publish_failure")
        await asyncio.Future()


def _setup(
    tmp_path: Path, mode: str
) -> tuple[_ProbeCoordinator, _RuntimePort, ObservationIngestRequest]:
    codex_id = f"release-{mode}"
    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    session_commitment = local.bind_codex_session(workspace, codex_id)
    task_id = _id(IdKind.TASK)
    session_id = _id(IdKind.SESSION)
    writer_id = observation_writer_id(task_id, session_id)
    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=codex_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=None,
    )
    db: Any = apsw.Connection(":memory:")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    initialize_bundle(db, {"task_id": task_id, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    runtime_value = type(
        "RuntimeValue",
        (),
        {
            "task_id": task_id,
            "session_id": session_id,
            "writer_id": writer_id,
            "observation": store,
        },
    )()
    runtime_port = _RuntimePort(runtime_value)

    def load_mapping(_codex_session_id: str, *, _state: Path | None = None) -> LifecycleMapping:
        del _codex_session_id, _state
        return mapping

    coordinator = _ProbeCoordinator(
        publish_mode=mode,
        runtime=runtime_port,  # type: ignore[arg-type]
        local=local,
        clock=FixedClock(),
        ids=FixedIds(),
        state_root=tmp_path,
        mapping_loader=load_mapping,
    )
    envelope = ObservationEnvelope(
        session_commitment=session_commitment,
        event_kind="PreToolUse",
        source_identity=f"hook:runtime-release:{mode}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, "hmac-sha256:" + "ab" * 32, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(
            {
                "tool_name": "shell",
                "tool_call_id": f"release-{mode}",
                "correlation_id": f"release-{mode}",
            }
        ),
        content_object_refs=(),
        gap_codes=(),
    )
    return coordinator, runtime_port, ObservationIngestRequest(codex_id, envelope)


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["raise", "cancel"])
async def test_ingest_finalizer_always_releases_runtime_on_backlog_cleanup_failure(
    tmp_path: Path, mode: str
) -> None:
    coordinator, runtime_port, request = _setup(tmp_path, mode)
    task = asyncio.create_task(coordinator.ingest_request(request))
    await asyncio.wait_for(coordinator.publish_entered.wait(), 5)
    if mode == "raise":
        with pytest.raises(RuntimeError, match="publish_failure"):
            await task
    else:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert runtime_port.releases == 1
    coordinator.close()
