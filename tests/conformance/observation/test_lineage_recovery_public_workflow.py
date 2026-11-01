"""Crash-window conformance for durable lineage lifecycle reconciliation."""

from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import finishup.application.start as start_module
from builders.multi_agent import (
    MultiAgentService,
    multi_agent_service,
    relock_and_reopen_multi_agent_service,
)
from finishup.adapters.sqlite.lineage_catalog import SqliteLineageStore
from finishup.application.lineage import DelegationOperationState, DelegationPhase, LineageSnapshot
from finishup.application.lineage_recovery import lineage_recovery_runtime
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.config.models import FinishUpConfig, LineageSettings
from finishup.domain.coordination import SessionHealth, WorkState
from finishup.domain.events import AcceptedEvent, WorkAbandonedPayload
from finishup.ports.control import RepositoryPrivacyContext
from finishup.protocol.coverage import PublicationChannel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import PublishWorkRequest, StartRequest, StatusRequest

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
# #1239: a top-level task now keeps its open work for the long horizon. These tests exercise
# crash safety and deadline renewal on one top-level task, so they pin the horizon to the window.
_TOP_LEVEL_AT_WINDOW = FinishUpConfig(
    lineage=LineageSettings(top_level_contact_lost_horizon_seconds=300)
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:recovery", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


async def test_append_before_lineage_sync_is_reconciled_on_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        started = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Crash window",
                    "workspace_ref": str(workspace),
                    "external_ref": "crash-window",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        before = await app.start_catalog.task_lineage(started.task_id)
        assert before is not None and before.work_state is WorkState.OPEN

        async def fail_after_append(
            _app: object, _request: object, _payloads: tuple[object, ...], **_result: object
        ) -> None:
            raise RuntimeError("simulated_crash_after_ledger_append")

        original = Application._sync_lineage_publication  # pyright: ignore[reportPrivateUsage]
        monkeypatch.setattr(Application, "_sync_lineage_publication", fail_after_append)
        with pytest.raises(RuntimeError, match="simulated_crash_after_ledger_append"):
            await app.publish_work(
                PublishWorkRequest.model_validate(
                    {
                        **_identity(),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "expected_frontier": started.frontier.model_dump(mode="json"),
                        "event_drafts": [
                            {
                                "event_id": new_id(IdKind.EVENT),
                                "schema": {"name": "work_closed", "version": "1.0.0"},
                                "occurred_at": "2026-09-05T12:00:00.000Z",
                                "causal_parents": [],
                                "payload": {},
                                "artifact_refs": [],
                                "evidence_refs": [],
                            }
                        ],
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        monkeypatch.setattr(Application, "_sync_lineage_publication", original)

        stale = await app.start_catalog.task_lineage(started.task_id)
        assert stale is not None and stale.work_state is WorkState.OPEN

        # A public child admission races the append-before-sync crash window.  START must repair
        # the accepted ledger event while holding the publication lock, then refuse the now
        # terminal parent instead of minting from the stale OPEN catalog projection.
        with pytest.raises(PublicOperationError) as closed_parent:
            await app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create",
                        "task_title": "Child after crashed close",
                        "workspace_ref": str(workspace),
                        "external_ref": "child-after-crashed-close",
                        "parent_session_id": started.session_id,
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert closed_parent.value.code is PublicErrorCode.SESSION_CONFLICT

        await app.recover_lineage()
        repaired = await app.start_catalog.task_lineage(started.task_id)
        assert repaired is not None and repaired.work_state is WorkState.CLOSED

        # A periodic/restart retry replays the same durable event without a second transition.
        await app.recover_lineage()
        replayed = await app.start_catalog.task_lineage(started.task_id)
        assert replayed is not None and replayed.work_state is WorkState.CLOSED


async def test_reclaimed_delegation_finishes_after_parent_event_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Delegation parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "delegation-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        request = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": "Delegation child",
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        )
        original = start_module._append_delegation_event  # pyright: ignore[reportPrivateUsage]

        async def fail_once(_app: object, _operation: object) -> None:
            raise RuntimeError("simulated_crash_after_child_bundle")

        monkeypatch.setattr(start_module, "_append_delegation_event", fail_once)
        with pytest.raises(RuntimeError, match="simulated_crash_after_child_bundle"):
            await app.start(request, repository_privacy_context=_REPOSITORY)
        monkeypatch.setattr(start_module, "_append_delegation_event", original)

        lineage = app.lineage
        assert lineage is not None
        operation = await lineage.store.get_operation(request.request_id)
        assert operation is not None
        assert operation.phase is DelegationPhase.CHILD_BUNDLE_READY
        assert operation.state is DelegationOperationState.PENDING

        # The ready maintenance recovery path reclaims and completes the same operation. It does
        # not mint another child or require a second parent request.
        await lineage.store.save_operation(
            replace(operation, lease_expires_at=service.clock.now_utc())
        )
        await app.recover_lineage()
        recovered = await lineage.store.get_operation(request.request_id)
        assert recovered is not None
        assert recovered.phase is DelegationPhase.TERMINAL
        assert recovered.state is DelegationOperationState.COMPLETE
        replayed = await app.start(request, repository_privacy_context=_REPOSITORY)
        assert replayed.task_id == recovered.child_task_id


async def _abandonment_events(app: Application, task: str) -> tuple[AcceptedEvent, ...]:
    route = await app.start_catalog.task_route(task)
    assert route is not None
    runtime = await lineage_recovery_runtime(app, task)
    try:
        events: dict[str, AcceptedEvent] = {}
        sessions = await app.start_catalog.task_session_states(task)
        for session in {route.session_id, *(state.session_id for state in sessions)}:
            async for record in runtime.ledger.load_events(session):
                if isinstance(record, AcceptedEvent) and isinstance(
                    record.payload, WorkAbandonedPayload
                ):
                    events[str(record.event_id)] = record
        return tuple(events.values())
    finally:
        await app.runtime.release(runtime)


async def _parent(service: MultiAgentService, workspace: Path) -> StartInternalResult:
    return await service.app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "create",
                "task_title": "Recovery parent",
                "workspace_ref": str(workspace),
                "external_ref": "recovery-parent",
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _delegate(service: MultiAgentService, parent: StartInternalResult) -> StartInternalResult:
    return await service.app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": "Recovery child",
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def test_abandonment_append_survives_catalog_failure_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_TOP_LEVEL_AT_WINDOW) as service:
        parent = await _parent(service, workspace)
        service.clock.advance(seconds=61)
        await service.app.recover_lineage()
        service.clock.advance(seconds=301)
        save = SqliteLineageStore.save_task

        async def fail_abandonment(store: SqliteLineageStore, snapshot: LineageSnapshot) -> None:
            if snapshot.work_state is WorkState.ABANDONED:
                raise RuntimeError("catalog_after_append")
            await save(store, snapshot)

        monkeypatch.setattr(SqliteLineageStore, "save_task", fail_abandonment)
        with pytest.raises(RuntimeError, match="catalog_after_append"):
            await service.app.recover_lineage()
        before = await service.app.start_catalog.task_lineage(parent.task_id)
        assert before is not None and before.work_state is WorkState.OPEN
        events = await _abandonment_events(service.app, parent.task_id)
        assert len(events) == 1
        payload = events[0].payload
        assert isinstance(payload, WorkAbandonedPayload)
        assert payload.service_stamped is True
        assert payload.reason_code == "contact_lost"
        assert events[0].publication_channel is PublicationChannel.ENGINE_DERIVED
        monkeypatch.setattr(SqliteLineageStore, "save_task", save)
        # #1239: the same session's late close supersedes the service's contact_lost guess, even
        # inside the append-before-sync window where only the ledger records the abandonment.
        await service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "expected_frontier": parent.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "work_closed", "version": "1.0.0"},
                            "occurred_at": "2026-09-05T12:10:00.000Z",
                            "causal_parents": [],
                            "payload": {},
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        lineage = service.app.lineage
        assert lineage is not None
        closed = await lineage.store.get_task(parent.task_id)
        assert closed is not None and closed.work_state is WorkState.CLOSED
        await relock_and_reopen_multi_agent_service(service)
        await service.app.recover_lineage()
        # Replay of [work_abandoned(contact_lost), work_closed] keeps the close and records the
        # reversed abandonment as history; the service event is never appended twice.
        assert service.app.lineage is not None
        repaired = await service.app.lineage.store.get_task(parent.task_id)
        assert repaired is not None and repaired.work_state is WorkState.CLOSED
        assert repaired.abandonment_reason == "contact_lost"
        assert await _abandonment_events(service.app, parent.task_id) == events
        await service.app.recover_lineage()
        assert await _abandonment_events(service.app, parent.task_id) == events


async def test_expired_unclaimed_child_has_durable_outcome_without_lost_session(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    config = FinishUpConfig(lineage=LineageSettings(attach_handle_ttl_seconds=1))
    async with multi_agent_service(tmp_path / "state", config=config) as service:
        parent = await _parent(service, workspace)
        delegated = await _delegate(service, parent)
        service.clock.advance(seconds=2)
        await service.app.recover_lineage()
        lineage = service.app.lineage
        assert lineage is not None
        child = await lineage.store.get_task(delegated.task_id)
        assert child is not None
        assert child.work_state is WorkState.ABANDONED
        assert child.session_health is SessionHealth.ENDED
        assert child.contact_lost_at is None
        events = await _abandonment_events(service.app, delegated.task_id)
        assert len(events) == 1
        assert isinstance(events[0].payload, WorkAbandonedPayload)
        assert events[0].payload.reason_code == "attach_handle_expired"
        status = await service.app.lineage_status(parent.task_id, parent.session_id)
        assert (
            next(row for row in status.children if row.task_id == delegated.task_id).work_state
            is WorkState.ABANDONED
        )
        with pytest.raises(PublicOperationError) as refused:
            await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "attach",
                        "task_title": "Recovery child",
                        "attach_handle": delegated.as_wire()["attach_handle"],
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert refused.value.safe_details["reason_code"] == "attach_handle_revoked"
        await relock_and_reopen_multi_agent_service(service)
        await service.app.recover_lineage()
        assert await _abandonment_events(service.app, delegated.task_id) == events


async def test_activity_clears_old_deadline_and_grants_new_contact_loss_window(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_TOP_LEVEL_AT_WINDOW) as service:
        parent = await _parent(service, workspace)
        service.clock.advance(seconds=61)
        await service.app.recover_lineage()
        service.clock.advance(seconds=200)
        await service.app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "view": "compact",
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert service.app.lineage is not None
        renewed = await service.app.lineage.store.get_task(parent.task_id)
        assert renewed is not None and renewed.session_health is SessionHealth.ACTIVE
        assert renewed.contact_lost_at is None and renewed.abandonment_deadline is None
        service.clock.advance(seconds=61)
        await service.app.recover_lineage()
        service.clock.advance(seconds=100)
        await service.app.recover_lineage()
        still_open = await service.app.lineage.store.get_task(parent.task_id)
        assert still_open is not None and still_open.work_state is WorkState.OPEN
        assert await _abandonment_events(service.app, parent.task_id) == ()
        service.clock.advance(seconds=201)
        await service.app.recover_lineage()
        assert len(await _abandonment_events(service.app, parent.task_id)) == 1
