"""Injected-clock liveness scenarios for native work that outlasts one session lease (#837).

Every scenario runs the production READY composition: the SQLite catalog, lineage store, host
lineage registry, task ledgers, and the recovery sweep are real.  Host evidence is offered through
the same renewal hook the observation coordinator uses, with the host event's own receipt time.
Only the clock is injected, so each deadline below is an exact recorded instant, not a sleep.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import MultiAgentService, multi_agent_service
from finishup.adapters.sqlite.lineage_catalog import SqliteLineageStore
from finishup.application.lineage import LineageSnapshot
from finishup.application.lineage_recovery import (
    lineage_recovery_runtime,
    observed_activity_renewal,
)
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.config.models import FinishUpConfig, LineageSettings
from finishup.domain.coordination import SESSION_LEASE_SECONDS, SessionHealth, WorkState
from finishup.domain.events import AcceptedEvent, LedgerRecord, WorkAbandonedPayload
from finishup.domain.host_lineage import host_lineage_from_payload
from finishup.domain.observation import ObservationSource
from finishup.domain.values import format_rfc3339_millis
from finishup.kernel.check_standing import check_standing
from finishup.kernel.reducers import replay
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.ledger import CheckCommitResult
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
_HOST_SESSION = "hmac-sha256:" + "c" * 64
_WINDOW = 300
# #1239: a top-level task now keeps its open work for the long horizon. These tests exercise the
# evidence, hold and successor rules on one top-level task, so they pin the horizon to the window.
_TOP_LEVEL_AT_WINDOW = FinishUpConfig(
    lineage=LineageSettings(top_level_contact_lost_horizon_seconds=_WINDOW)
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:native-liveness", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.3.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


async def _create(
    service: MultiAgentService, workspace: Path, external_ref: str
) -> StartInternalResult:
    return await service.app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "create",
                "task_title": "Native liveness parent",
                "workspace_ref": str(workspace),
                "external_ref": external_ref,
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _delegate(
    service: MultiAgentService, parent: StartInternalResult, title: str
) -> StartInternalResult:
    return await service.app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": title,
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _attach_child(
    service: MultiAgentService, delegated: StartInternalResult, title: str
) -> StartInternalResult:
    assert delegated.attach_handle is not None
    return await service.app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "attach",
                "task_title": title,
                "attach_handle": delegated.as_wire()["attach_handle"],
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _status(service: MultiAgentService, task: StartInternalResult) -> object:
    return await service.app.status(
        StatusRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "view": "compact",
                "limit": "1",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


def _frontier_json(frontier: object) -> Mapping[str, object]:
    as_wire = getattr(frontier, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    return cast(Mapping[str, object], getattr(frontier, "model_dump")(mode="json"))


async def _publish_action(
    service: MultiAgentService, task: StartInternalResult, description: str
) -> PublishWorkInternalResult:
    status = await _status(service, task)
    result = await service.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(getattr(status, "head_frontier")),
                "event_drafts": (
                    {
                        "event_id": new_id(IdKind.EVENT),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-05T12:00:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "action_id": new_id(IdKind.ACTION),
                            "action_kind": "review",
                            "description": description,
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _close(service: MultiAgentService, task: StartInternalResult) -> None:
    status = await _status(service, task)
    await service.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(getattr(status, "head_frontier")),
                "event_drafts": (
                    {
                        "event_id": new_id(IdKind.EVENT),
                        "schema": {"name": "work_closed", "version": "1.0.0"},
                        "occurred_at": "2026-09-05T12:00:00.000Z",
                        "causal_parents": (),
                        "payload": {},
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _check(service: MultiAgentService, task: StartInternalResult) -> CheckCommitResult:
    # Record current child facts first, as the maintenance lane does before a parent check.
    sweep = getattr(service.app, "observation_sweep", None)
    if sweep is not None:
        await sweep()
    status = await _status(service, task)
    result = await service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(getattr(status, "head_frontier")),
                "mode": "deterministic_only",
                "max_findings": "10",
                "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _receipt(
    service: MultiAgentService,
    task: StartInternalResult,
    checked: CheckCommitResult,
    *,
    request_id: str,
) -> Mapping[str, object]:
    identity = _identity()
    identity["request_id"] = request_id
    receipt = await service.app.receipt(
        ReceiptRequest.model_validate(
            {
                **identity,
                "task_id": task.task_id,
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(checked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert receipt.document is not None
    return cast(Mapping[str, object], receipt.document)


def _child_ids(document: Mapping[str, object]) -> set[object]:
    section = cast(Mapping[str, object], document["children"])
    rows = cast(Sequence[Mapping[str, object]], section["children"])
    return {row["child_task_id"] for row in rows}


async def _abandonment_events(app: Application, task: str) -> tuple[AcceptedEvent, ...]:
    runtime = await lineage_recovery_runtime(app, task)
    try:
        events: dict[str, AcceptedEvent] = {}
        sessions = await app.start_catalog.task_session_states(task)
        for session in {runtime.session_id, *(state.session_id for state in sessions)}:
            async for record in runtime.ledger.load_events(session):
                if isinstance(record, AcceptedEvent) and isinstance(
                    record.payload, WorkAbandonedPayload
                ):
                    events[str(record.event_id)] = record
        return tuple(events.values())
    finally:
        await app.runtime.release(runtime)


async def _work(app: Application, task: StartInternalResult) -> WorkState:
    lineage = await app.start_catalog.task_lineage(task.task_id)
    assert lineage is not None
    return lineage.work_state


async def _health(app: Application, task: StartInternalResult) -> SessionHealth:
    state = await app.start_catalog.task_session_state(task.session_id)
    assert state is not None
    return state.health


async def _offer(service: MultiAgentService, task: StartInternalResult, observed: datetime) -> None:
    """Offer one admitted host event exactly as the observation coordinator's hook does."""

    lineage = service.app.lineage
    assert lineage is not None
    await lineage.bind_host_session_commitment(
        task_id=task.task_id,
        session_id=task.session_id,
        session_commitment=_HOST_SESSION,
    )
    renew = observed_activity_renewal(service.app.start_catalog, lineage, service.app.clock)
    await renew(task.task_id, task.session_id, task.writer_id, observed)


async def _subagent(
    service: MultiAgentService, parent: StartInternalResult, event_kind: str, agent_id: str
) -> None:
    """Record one native Claude subagent lifecycle signal under the parent, then offer it."""

    registry = service.app.host_lineage_registry
    assert registry is not None
    observation = host_lineage_from_payload("claude", event_kind, {"agent_id": agent_id})
    assert observation is not None
    await registry.record_host_lineage_observation(
        parent.task_id,
        observation,
        observed_session_commitment=_HOST_SESSION,
        source=ObservationSource.CLAUDE_HOOK,
    )
    await _offer(service, parent, service.clock.now_utc())


async def test_delayed_host_evidence_restores_contact_from_its_own_time(tmp_path: Path) -> None:
    """Queued or swept rows prove contact at receipt time, whatever their delivery time."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_TOP_LEVEL_AT_WINDOW) as service:
        app = service.app
        assert app.lineage is not None
        start = service.clock.now_utc()
        parent = await _create(service, workspace, "delayed-admission")

        service.clock.advance(seconds=61)
        await app.recover_lineage()
        assert await _health(app, parent) is SessionHealth.CONTACT_LOST

        # Received at +30 while the lease held; delivered only after the sweep marked the loss.
        await _offer(service, parent, start + timedelta(seconds=30))
        state = await app.start_catalog.task_session_state(parent.session_id)
        assert state is not None and state.health is SessionHealth.ACTIVE
        assert state.lease_expires_at == start + timedelta(seconds=30 + SESSION_LEASE_SECONDS)
        restored = await app.lineage.store.get_task(parent.task_id)
        assert restored is not None and restored.abandonment_deadline is None

        service.clock.advance(seconds=30)  # +91: the evidence-anchored lease has ended.
        await app.recover_lineage()
        assert await _health(app, parent) is SessionHealth.CONTACT_LOST
        lost = await app.lineage.store.get_task(parent.task_id)
        assert lost is not None
        assert lost.abandonment_deadline == start + timedelta(seconds=91 + _WINDOW)

        # Evidence older than the recorded contact is inert.
        await _offer(service, parent, start + timedelta(seconds=20))
        assert await app.lineage.store.get_task(parent.task_id) == lost

        # A row received at +80 but delivered at +200 ran out at +140, after the recorded loss.
        service.clock.advance(seconds=109)
        await _offer(service, parent, start + timedelta(seconds=80))
        moved = await app.lineage.store.get_task(parent.task_id)
        assert moved is not None and moved.session_health is SessionHealth.CONTACT_LOST
        assert moved.contact_lost_at == start + timedelta(seconds=140)
        assert moved.abandonment_deadline == start + timedelta(seconds=140 + _WINDOW)
        await _offer(service, parent, start + timedelta(seconds=80))  # duplicate delivery
        assert await app.lineage.store.get_task(parent.task_id) == moved

        service.clock.advance(seconds=200)  # +400: past the stale +391 deadline.
        await app.recover_lineage()
        assert await _work(app, parent) is WorkState.OPEN
        assert await _abandonment_events(app, parent.task_id) == ()

        # Genuine disconnect: once the delivered evidence also runs out, the window applies.
        service.clock.advance(seconds=41)  # +441
        await app.recover_lineage()
        assert await _work(app, parent) is WorkState.ABANDONED
        assert len(await _abandonment_events(app, parent.task_id)) == 1


async def test_native_subagent_run_holds_parent_contact_until_its_stop(tmp_path: Path) -> None:
    """The #837 native sequence: a parent waits on native subagents far past lease + window."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_TOP_LEVEL_AT_WINDOW) as service:
        app = service.app
        parent = await _create(service, workspace, "native-subagent-parent")
        await _subagent(service, parent, "SubagentStart", "reviewer")

        # Twenty minutes without one parent event, swept at a lagging two-minute cadence.
        for _ in range(10):
            service.clock.advance(seconds=120)
            await app.recover_lineage()
            assert await _work(app, parent) is WorkState.OPEN
            assert await _health(app, parent) is SessionHealth.ACTIVE
        assert await _abandonment_events(app, parent.task_id) == ()

        # The parent can still mint child work when it resumes.
        delegated = await _delegate(service, parent, "Follow-up child")
        assert delegated.attach_handle is not None

        # Once the host reports the stop, the hold ends and ordinary expiry resumes.
        await _subagent(service, parent, "SubagentStop", "reviewer")
        service.clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
        await app.recover_lineage()
        assert await _health(app, parent) is SessionHealth.CONTACT_LOST
        service.clock.advance(seconds=_WINDOW + 1)
        await app.recover_lineage()
        assert await _work(app, parent) is WorkState.ABANDONED


async def test_host_child_without_a_stop_is_released_by_the_hold_bound(tmp_path: Path) -> None:
    """A host that dies mid-subagent never reports the stop; the bound still ends contact."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_TOP_LEVEL_AT_WINDOW) as service:
        app = service.app
        assert app.lineage is not None
        bound = app.lineage.config.native_operation_hold_seconds
        parent = await _create(service, workspace, "native-disconnect-parent")
        await _subagent(service, parent, "SubagentStart", "lost-helper")

        service.clock.advance(seconds=bound - 600)
        await app.recover_lineage()
        assert await _health(app, parent) is SessionHealth.ACTIVE

        service.clock.advance(seconds=700)  # The start is now older than the bound.
        await app.recover_lineage()
        assert await _health(app, parent) is SessionHealth.CONTACT_LOST
        assert await _work(app, parent) is WorkState.OPEN
        service.clock.advance(seconds=_WINDOW + 1)
        await app.recover_lineage()
        assert await _work(app, parent) is WorkState.ABANDONED
        events = await _abandonment_events(app, parent.task_id)
        assert len(events) == 1
        assert isinstance(events[0].payload, WorkAbandonedPayload)
        assert events[0].payload.reason_code == "contact_lost"


async def test_cooperative_publications_keep_long_hookless_work_open(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await _create(service, workspace, "cooperative-parent")
        for index in range(6):
            service.clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
            await app.recover_lineage()
            assert await _health(app, parent) is SessionHealth.CONTACT_LOST
            service.clock.advance(seconds=_WINDOW - SESSION_LEASE_SECONDS - 2)
            await _publish_action(service, parent, f"Cooperative progress {index}.")
            await app.recover_lineage()
            assert await _health(app, parent) is SessionHealth.ACTIVE
        assert await _work(app, parent) is WorkState.OPEN
        assert await _abandonment_events(app, parent.task_id) == ()


async def test_explicit_close_is_never_abandoned_and_refuses_resume_atomically(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await _create(service, workspace, "closed-parent")
        await _close(service, parent)
        service.clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
        await app.recover_lineage()
        service.clock.advance(seconds=_WINDOW + 1)
        await app.recover_lineage()
        assert await _work(app, parent) is WorkState.CLOSED
        assert await _abandonment_events(app, parent.task_id) == ()

        route = await app.start_catalog.resolve_route(parent.session_id)
        sessions = await app.start_catalog.task_session_states(parent.task_id)
        with pytest.raises(PublicOperationError) as refused:
            await app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create_or_attach",
                        "task_title": "Native liveness parent",
                        "workspace_ref": str(workspace),
                        "external_ref": "closed-parent",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert refused.value.code is PublicErrorCode.SESSION_CONFLICT
        assert refused.value.safe_details["reason_code"] == "lineage_resume_work_terminal"
        assert refused.value.safe_details["continuation"] == "lineage_successor_task"
        # Nothing was reserved or rotated: the held session still routes and reads.
        assert await app.start_catalog.resolve_route(parent.session_id) == route
        assert await app.start_catalog.task_session_states(parent.task_id) == sessions
        await _status(service, parent)


async def test_abandoned_parent_continues_through_a_successor_with_receipts(
    tmp_path: Path,
) -> None:
    """Supported recovery after abandonment: history stays, new work moves to a successor."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_TOP_LEVEL_AT_WINDOW) as service:
        app = service.app
        parent = await _create(service, workspace, "abandoned-parent")
        child = await _attach_child(
            service, await _delegate(service, parent, "Original child"), "Original child"
        )
        await _publish_action(service, parent, "Parent work before the silence.")
        before_check = await _check(service, parent)
        receipt_request = new_id(IdKind.REQUEST)
        before = await _receipt(service, parent, before_check, request_id=receipt_request)
        assert _child_ids(before) == {child.task_id}

        # The parent goes silent with no host evidence at all; its child keeps publishing.
        service.clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
        await _publish_action(service, child, "Child progress during the parent's silence.")
        await app.recover_lineage()
        service.clock.advance(seconds=_WINDOW + 1)
        await _publish_action(service, child, "More child progress.")
        await app.recover_lineage()
        assert await _work(app, parent) is WorkState.ABANDONED
        assert await _work(app, child) is WorkState.OPEN

        # New child work from the terminal parent is refused with the successor continuation.
        with pytest.raises(PublicOperationError) as delegation:
            await _delegate(service, parent, "Refused child")
        assert delegation.value.code is PublicErrorCode.SESSION_CONFLICT
        assert delegation.value.safe_details["reason_code"] == "lineage_parent_work_terminal"
        assert delegation.value.safe_details["continuation"] == "lineage_successor_task"
        parent_lineage = await app.lineage_status(parent.task_id, parent.session_id)
        assert {row.task_id for row in parent_lineage.children} == {child.task_id}

        # Resuming the terminal task is refused before any route rotation.
        route = await app.start_catalog.resolve_route(parent.session_id)
        with pytest.raises(PublicOperationError) as resume:
            await app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create_or_attach",
                        "task_title": "Native liveness parent",
                        "workspace_ref": str(workspace),
                        "external_ref": "abandoned-parent",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert resume.value.safe_details["reason_code"] == "lineage_resume_work_terminal"
        assert resume.value.safe_details["continuation"] == "lineage_successor_task"
        assert await app.start_catalog.resolve_route(parent.session_id) == route

        # The held session keeps the honest record: late evidence, a new check, and a receipt
        # are accepted while work stays abandoned; the earlier receipt replays unchanged.
        await _publish_action(service, parent, "Late parent evidence after abandonment.")
        assert await _work(app, parent) is WorkState.ABANDONED
        after_check = await _check(service, parent)
        after = await _receipt(service, parent, after_check, request_id=new_id(IdKind.REQUEST))
        assert _child_ids(after) == {child.task_id}
        # #1239: the later receipt says the service abandoned the work, from the ledger event.
        limitations = next(
            cast(str, row["body"])
            for row in cast(Sequence[Mapping[str, object]], after["sections"])
            if row["key"] == "limitations_and_coverage"
        )
        assert "The service recorded this task's work as abandoned (reason contact_lost)" in (
            limitations
        )
        assert "the work is incomplete as recorded." in limitations
        assert await _receipt(service, parent, before_check, request_id=receipt_request) == before

        # The successor is ordinary open work in the same workspace and can delegate again.
        successor = await _create(service, workspace, "abandoned-parent-successor")
        assert successor.task_id != parent.task_id
        assert await _work(app, successor) is WorkState.OPEN
        follow_up = await _attach_child(
            service, await _delegate(service, successor, "Successor child"), "Successor child"
        )
        successor_lineage = await app.lineage_status(successor.task_id, successor.session_id)
        assert {row.task_id for row in successor_lineage.children} == {follow_up.task_id}
        parent_lineage = await app.lineage_status(parent.task_id, parent.session_id)
        assert {row.task_id for row in parent_lineage.children} == {child.task_id}
        successor_check = await _check(service, successor)
        successor_receipt = await _receipt(
            service, successor, successor_check, request_id=new_id(IdKind.REQUEST)
        )
        assert _child_ids(successor_receipt) == {follow_up.task_id}
        assert len(await _abandonment_events(app, parent.task_id)) == 1


async def test_a_quiet_child_whose_parent_waits_is_abandoned_and_its_close_reverses_it(
    tmp_path: Path,
) -> None:
    """#1239: the short window protects a waiting parent, and the child's own close still stands.

    The parent keeps working, so its child gets the short window and is abandoned for silence.
    The child was working all along: its close supersedes the guess, status says so, and the
    parent's manifest is refreshed right away.
    """

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        refreshed: list[str] = []

        async def refresh(child_task_id: str) -> None:
            refreshed.append(child_task_id)

        object.__setattr__(app, "lineage_parent_refresh", refresh)
        parent = await _create(service, workspace, "reversal-parent")
        child = await _attach_child(
            service, await _delegate(service, parent, "Quiet child"), "Quiet child"
        )
        service.clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
        await _publish_action(service, parent, "The parent keeps working.")
        await app.recover_lineage()
        service.clock.advance(seconds=_WINDOW + 1)
        await _publish_action(service, parent, "The parent is still working.")
        await app.recover_lineage()
        assert await _work(app, child) is WorkState.ABANDONED
        assert await _work(app, parent) is WorkState.OPEN
        lost = cast(StatusInternalResult, await _status(service, child))
        assert lost.task_lifecycle is not None
        assert lost.task_lifecycle["work_state"] == "abandoned"
        assert lost.task_lifecycle["abandonment_reason"] == "contact_lost"

        await _close(service, child)
        assert await _work(app, child) is WorkState.CLOSED
        assert refreshed == [child.task_id]
        assert len(await _abandonment_events(app, child.task_id)) == 1
        closed = cast(StatusInternalResult, await _status(service, child))
        assert closed.task_lifecycle is not None
        assert closed.task_lifecycle["work_state"] == "closed"
        assert closed.task_lifecycle["abandonment_reversed"] is True
        # The top-level parent, quiet for longer than the child's window, stays open meanwhile.
        service.clock.advance(seconds=SESSION_LEASE_SECONDS + _WINDOW + 2)
        await app.recover_lineage()
        assert await _work(app, parent) is WorkState.OPEN
        assert await _health(app, parent) is SessionHealth.CONTACT_LOST


async def _declare_quiet(
    service: MultiAgentService, task: StartInternalResult, seconds: int
) -> PublishWorkRequest:
    status = await _status(service, task)
    request = PublishWorkRequest.model_validate(
        {
            **_identity(),
            "session_id": task.session_id,
            "writer_id": task.writer_id,
            "expected_frontier": _frontier_json(getattr(status, "head_frontier")),
            "event_drafts": (
                {
                    "event_id": new_id(IdKind.EVENT),
                    "schema": {"name": "contact_expectation_declared", "version": "1.0.0"},
                    "occurred_at": "2026-09-05T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": {"expected_quiet_seconds": seconds, "reason_code": "long_build"},
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
        }
    )
    await service.app.publish_work(request, repository_privacy_context=_REPOSITORY)
    return request


async def _records(app: Application, task: str) -> tuple[LedgerRecord, ...]:
    runtime = await lineage_recovery_runtime(app, task)
    try:
        rows: dict[str, LedgerRecord] = {}
        sessions = await app.start_catalog.task_session_states(task)
        for session in {runtime.session_id, *(state.session_id for state in sessions)}:
            async for record in runtime.ledger.load_events(session):
                rows[str(record.event_id)] = record
        return tuple(sorted(rows.values(), key=lambda item: item.ledger.ingestion_sequence))
    finally:
        await app.runtime.release(runtime)


async def test_a_child_declares_a_quiet_build_and_is_abandoned_only_after_it(
    tmp_path: Path,
) -> None:
    """#1239 (D6): a declared quiet period moves a waiting parent's child deadline.

    The declaration is a recorded lineage fact: status shows it, it leaves the child's recorded
    check standing, and recovery restores it from the ledger if the catalog lost it.
    """

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        assert app.lineage is not None
        parent = await _create(service, workspace, "quiet-parent")
        child = await _attach_child(
            service, await _delegate(service, parent, "Quiet build"), "Quiet build"
        )
        await _publish_action(service, child, "Child work before the build.")
        await _check(service, child)
        declared_at = service.clock.now_utc()
        await _declare_quiet(service, child, 1_800)
        quiet_until = declared_at + timedelta(seconds=1_800)
        stored = await app.lineage.store.get_task(child.task_id)
        assert stored is not None and stored.quiet_until == quiet_until
        status = cast(StatusInternalResult, await _status(service, child))
        assert status.task_lifecycle is not None
        assert status.task_lifecycle["quiet_until"] == format_rfc3339_millis(quiet_until)
        records = await _records(app, child.task_id)
        assert check_standing(replay(records), records).superseded_by is None

        # The catalog loses the declaration (a crash after the ledger append); recovery replays it.
        lost = await app.lineage.store.get_task(child.task_id)
        assert lost is not None
        await app.lineage.store.save_task(replace(lost, quiet_until=None))
        await app.recover_lineage()
        restored = await app.lineage.store.get_task(child.task_id)
        # Both run from the accepted time, so recovery restores exactly the same end.
        assert restored is not None and restored.quiet_until == quiet_until

        # The parent keeps working; the child is silent through its declared build.
        for _ in range(4):
            service.clock.advance(seconds=_WINDOW + 61)
            await _publish_action(service, parent, "The parent keeps working.")
            await app.recover_lineage()
        assert await _work(app, child) is WorkState.OPEN
        assert await _health(app, child) is SessionHealth.CONTACT_LOST
        service.clock.advance(seconds=1_800 + _WINDOW + 1 - 4 * (_WINDOW + 61))
        await _publish_action(service, parent, "The parent is still working.")
        await app.recover_lineage()
        assert await _work(app, child) is WorkState.ABANDONED


async def test_a_retried_quiet_declaration_moves_no_period(tmp_path: Path) -> None:
    """#1239: the period runs from its acceptance, so a retried request (a replay) moves nothing.

    Neither a retry after the period began nor a late retry of an earlier declaration replaces
    what the ledger's latest declaration set.
    """

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        assert app.lineage is not None
        task = await _create(service, workspace, "quiet-retry")
        first_at = service.clock.now_utc()
        first = await _declare_quiet(service, task, 1_800)
        service.clock.advance(seconds=300)
        retried = await app.publish_work(first, repository_privacy_context=_REPOSITORY)
        assert isinstance(retried, PublishWorkInternalResult) and retried.outcome == "replayed"
        stored = await app.lineage.store.get_task(task.task_id)
        assert stored is not None and stored.quiet_until == first_at + timedelta(seconds=1_800)

        service.clock.advance(seconds=120)
        second_at = service.clock.now_utc()
        await _declare_quiet(service, task, 600)
        service.clock.advance(seconds=120)
        await app.publish_work(first, repository_privacy_context=_REPOSITORY)
        stored = await app.lineage.store.get_task(task.task_id)
        assert stored is not None and stored.quiet_until == second_at + timedelta(seconds=600)
        await app.recover_lineage()
        assert await app.lineage.store.get_task(task.task_id) == stored


async def test_a_child_close_replayed_after_a_crash_refreshes_its_parent_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1239: the reversal refresh also runs when replay repairs a close the catalog missed."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        refreshed: list[str] = []

        async def refresh(child_task_id: str) -> None:
            refreshed.append(child_task_id)

        object.__setattr__(app, "lineage_parent_refresh", refresh)
        parent = await _create(service, workspace, "replay-reversal-parent")
        child = await _attach_child(
            service, await _delegate(service, parent, "Replayed child"), "Replayed child"
        )
        service.clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
        await _publish_action(service, parent, "The parent keeps working.")
        await app.recover_lineage()
        service.clock.advance(seconds=_WINDOW + 1)
        await _publish_action(service, parent, "The parent is still working.")
        await app.recover_lineage()
        assert await _work(app, child) is WorkState.ABANDONED

        save = SqliteLineageStore.save_task

        async def fail_close(store: SqliteLineageStore, snapshot: LineageSnapshot) -> None:
            if snapshot.work_state is WorkState.CLOSED:
                raise RuntimeError("catalog_after_append")
            await save(store, snapshot)

        monkeypatch.setattr(SqliteLineageStore, "save_task", fail_close)
        with pytest.raises(Exception):  # noqa: B017 - the append landed; the catalog sync failed
            await _close(service, child)
        monkeypatch.setattr(SqliteLineageStore, "save_task", save)
        assert await _work(app, child) is WorkState.ABANDONED
        assert refreshed == []

        await app.recover_lineage()
        assert await _work(app, child) is WorkState.CLOSED
        assert refreshed == [child.task_id]
        # Later sweeps replay the same close onto a closed row and refresh nothing.
        await app.recover_lineage()
        assert refreshed == [child.task_id]
