"""Adversarial public recovery checks for the durable delegation phase machine.

Each row injects a failure at one external delegation boundary, then retries the exact public
request.  The assertions inspect the durable operation, route, handle, and parent event so a
successful retry cannot hide a duplicate child or a second parent declaration.
"""

from __future__ import annotations

import subprocess
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import cast

import pytest

import finishup.application.start as start_module
from builders.multi_agent import MultiAgentService, multi_agent_service
from finishup.adapters.sqlite.lineage_catalog import SqliteLineageStore
from finishup.adapters.sqlite.start_catalog import SqliteStartCatalog
from finishup.application.lineage import (
    DelegationOperation,
    DelegationOperationState,
    DelegationPhase,
    LineageCoordinator,
)
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.config.models import FinishUpConfig, LineageSettings
from finishup.domain.coordination import LineageAcceptance
from finishup.domain.events import AcceptedEvent, DelegationDeclaredPayload
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.ports.start_catalog import SafeReason, StartPhase
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:delegation-phase-matrix", "actor_type": "harness"},
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


def _delegate_request(parent_session_id: str, *, title: str = "phase child") -> StartRequest:
    return StartRequest.model_validate(
        {
            **_identity(),
            "mode": "delegate",
            "task_title": title,
            "session_id": parent_session_id,
            "requested_view": "compact",
        }
    )


async def _delegation_events(
    app: Application, session_id: str, writer_id: str
) -> tuple[AcceptedEvent, ...]:
    runtime = await app.runtime.route(
        RouteCommand(
            session_id,
            writer_id,
            RouteAccess.PAYLOAD_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        events: list[AcceptedEvent] = []
        records = cast(AsyncIterator[object], runtime.ledger.load_events(session_id))
        async for record in records:
            if isinstance(record, AcceptedEvent) and isinstance(
                record.payload, DelegationDeclaredPayload
            ):
                events.append(record)
        return tuple(events)
    finally:
        await app.runtime.release(runtime)


async def _assert_single_delegation_state(
    service: MultiAgentService,
    parent: StartInternalResult,
    request: StartRequest,
    result: StartInternalResult,
) -> None:
    app = service.app
    lineage = app.lineage
    assert lineage is not None
    store = cast(SqliteLineageStore, lineage.store)
    operations = await store.list_operations()
    assert len(operations) == 1
    operation = operations[0]
    assert operation.operation_id == request.request_id
    assert operation.state is DelegationOperationState.COMPLETE
    assert operation.phase is DelegationPhase.TERMINAL
    assert operation.child_task_id == result.task_id

    handle = await store.get_handle(operation.handle_digest)
    assert handle is not None
    assert handle.task_id == operation.child_task_id
    assert result.attach_handle is not None
    assert handle.value == result.attach_handle.value

    catalog = cast(SqliteStartCatalog, app.start_catalog)
    routes = await catalog.recovery_routes()
    assert {route.task_id for route in routes} == {
        parent.task_id,
        operation.child_task_id,
    }
    children = await store.list_children(parent.task_id)
    assert tuple(child.task_id for child in children) == (operation.child_task_id,)
    child = await store.get_task(operation.child_task_id)
    assert child is not None
    assert child.acceptance is LineageAcceptance.ACCEPTED

    events = await _delegation_events(app, parent.session_id, parent.writer_id)
    assert len(events) == 1
    payload = events[0].payload
    assert isinstance(payload, DelegationDeclaredPayload)
    assert str(payload.child_task_id) == operation.child_task_id
    assert payload.handle_digest == operation.handle_digest


@pytest.mark.parametrize(
    "boundary",
    (
        "lineage_reserved",
        "child_bundle_ready",
        "parent_event_committed",
        "handle_published",
    ),
)
async def test_public_delegation_retries_every_phase_boundary_without_duplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    """A crash after each boundary is recovered by the same request identity."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "phase parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "phase-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        request = _delegate_request(parent.session_id)

        if boundary in {"lineage_reserved", "child_bundle_ready"}:
            original = cast(
                Callable[[Application, DelegationOperation], Awaitable[None]],
                start_module._provision_delegated_child,  # pyright: ignore[reportPrivateUsage]
            )

            async def fail_at_bundle(app_arg: Application, operation: DelegationOperation) -> None:
                if boundary == "child_bundle_ready":
                    await original(app_arg, operation)
                raise RuntimeError(f"simulated_{boundary}")

            monkeypatch.setattr(start_module, "_provision_delegated_child", fail_at_bundle)
        elif boundary == "parent_event_committed":
            original = cast(
                Callable[[Application, DelegationOperation], Awaitable[None]],
                start_module._append_delegation_event,  # pyright: ignore[reportPrivateUsage]
            )

            async def fail_at_event(app_arg: Application, operation: DelegationOperation) -> None:
                await original(app_arg, operation)
                raise RuntimeError(f"simulated_{boundary}")

            monkeypatch.setattr(start_module, "_append_delegation_event", fail_at_event)
        else:
            lineage_type = LineageCoordinator
            original = lineage_type.publish_attach_handle

            async def fail_at_handle(
                coordinator: LineageCoordinator, operation_id: str, request_digest: str
            ) -> object:
                await original(coordinator, operation_id, request_digest)
                raise RuntimeError(f"simulated_{boundary}")

            monkeypatch.setattr(lineage_type, "publish_attach_handle", fail_at_handle)

        with pytest.raises(RuntimeError, match=f"simulated_{boundary}"):
            await app.start(request, repository_privacy_context=_REPOSITORY)

        lineage = app.lineage
        assert lineage is not None
        pending = await lineage.store.get_operation(request.request_id)
        assert pending is not None
        expected_phase = {
            "lineage_reserved": DelegationPhase.LINEAGE_RESERVED,
            "child_bundle_ready": DelegationPhase.LINEAGE_RESERVED,
            "parent_event_committed": DelegationPhase.CHILD_BUNDLE_READY,
            "handle_published": DelegationPhase.HANDLE_PUBLISHED,
        }[boundary]
        assert pending.phase is expected_phase
        assert pending.state is DelegationOperationState.PENDING

        # Restore the injected failure before retrying the exact public request.  The original
        # request id and body must reclaim the durable operation rather than mint a sibling.
        monkeypatch.undo()
        retried = await app.start(request, repository_privacy_context=_REPOSITORY)
        assert retried.task_id == pending.child_task_id
        assert retried.attach_handle is not None
        await _assert_single_delegation_state(service, parent, request, retried)

        # A following recovery sweep must be a no-op for the completed operation and preserve the
        # same child and parent event.  This also exercises the public recovery entry point after
        # the retry path has closed the operation.
        await app.recover_lineage()
        replayed = await app.start(request, repository_privacy_context=_REPOSITORY)
        assert replayed.task_id == retried.task_id
        assert replayed.attach_handle == retried.attach_handle
        await _assert_single_delegation_state(service, parent, request, replayed)


async def test_public_attach_handle_expiry_is_typed_and_does_not_rotate_child(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    config = FinishUpConfig(lineage=LineageSettings(attach_handle_ttl_seconds=1))
    async with multi_agent_service(tmp_path / "state", config=config) as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "expiry parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "expiry-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        delegated = await service.app.start(
            _delegate_request(parent.session_id, title="expiry child"),
            repository_privacy_context=_REPOSITORY,
        )
        assert delegated.attach_handle is not None
        catalog = cast(SqliteStartCatalog, service.app.start_catalog)
        before_routes = await catalog.recovery_routes()
        service.clock.advance(seconds=2)
        with pytest.raises(PublicOperationError) as expired:
            await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "attach",
                        "task_title": "expiry child",
                        "attach_handle": delegated.as_wire()["attach_handle"],
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert expired.value.code is PublicErrorCode.SESSION_CONFLICT
        assert expired.value.safe_details["reason_code"] == "attach_handle_expired"
        after_routes = await catalog.recovery_routes()
        assert tuple(route.task_id for route in after_routes) == tuple(
            route.task_id for route in before_routes
        )


async def test_same_session_attach_retry_is_idempotent_after_handle_consumption(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "attach retry parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "attach-retry-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        delegated = await service.app.start(
            _delegate_request(parent.session_id, title="attach retry child"),
            repository_privacy_context=_REPOSITORY,
        )
        assert delegated.attach_handle is not None
        attach = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "attach",
                "task_title": "attach retry child",
                "attach_handle": delegated.as_wire()["attach_handle"],
                "requested_view": "compact",
            }
        )
        first = await service.app.start(attach, repository_privacy_context=_REPOSITORY)
        # Expiry fences first consumption, but cannot strand an authenticated retry of the
        # already committed session after a response or host-correlation failure.
        service.clock.advance(seconds=301)
        second = await service.app.start(attach, repository_privacy_context=_REPOSITORY)
        assert (second.task_id, second.session_id, second.writer_id) == (
            first.task_id,
            first.session_id,
            first.writer_id,
        )
        lineage = service.app.lineage
        assert lineage is not None
        store = cast(SqliteLineageStore, lineage.store)
        operation = (await store.list_operations())[0]
        handle = await store.get_handle(operation.handle_digest)
        assert handle is not None and handle.consumed_session_id == first.session_id
        routes = await cast(SqliteStartCatalog, service.app.start_catalog).recovery_routes()
        assert len(routes) == 2


async def test_attach_crash_after_child_start_recovers_only_the_exact_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The window between a committed child start and handle consumption must be recoverable.

    A crash there leaves a started child route behind an unconsumed handle.  Once the handle
    expires, every fresh request is still refused, but the exact original request must be able to
    replay its committed start and finish the consumption without rotating the child route.
    """

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "attach crash parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "attach-crash-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        delegated = await service.app.start(
            _delegate_request(parent.session_id, title="attach crash child"),
            repository_privacy_context=_REPOSITORY,
        )
        assert delegated.attach_handle is not None
        wire_handle = delegated.as_wire()["attach_handle"]
        attach = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "attach",
                "task_title": "attach crash child",
                "attach_handle": wire_handle,
                "requested_view": "compact",
            }
        )
        catalog = cast(SqliteStartCatalog, service.app.start_catalog)
        lineage = service.app.lineage
        assert lineage is not None
        store = cast(SqliteLineageStore, lineage.store)
        operation = (await store.list_operations())[0]

        original_attach = LineageCoordinator._attach_locked  # pyright: ignore[reportPrivateUsage]
        crashes = 0

        async def crash_once(self: LineageCoordinator, **kwargs: object) -> object:
            nonlocal crashes
            if crashes == 0:
                crashes += 1
                raise RuntimeError("crash after child start, before handle consumption")
            return await original_attach(self, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(LineageCoordinator, "_attach_locked", crash_once)
        with pytest.raises(RuntimeError):
            await service.app.start(attach, repository_privacy_context=_REPOSITORY)
        monkeypatch.undo()
        assert crashes == 1

        handle = await store.get_handle(operation.handle_digest)
        assert handle is not None and handle.consumed_session_id is None
        routes_after_crash = await catalog.recovery_routes()
        assert len(routes_after_crash) == 2

        service.clock.advance(seconds=301)

        # A fresh request cannot use the expired capability, and does not rotate the child.
        with pytest.raises(PublicOperationError) as expired:
            await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "attach",
                        "task_title": "attach crash child",
                        "attach_handle": wire_handle,
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert expired.value.code is PublicErrorCode.SESSION_CONFLICT
        assert expired.value.safe_details["reason_code"] == "attach_handle_expired"
        handle = await store.get_handle(operation.handle_digest)
        assert handle is not None and handle.consumed_session_id is None

        # The exact committed request replays its start and finishes consumption.
        recovered = await service.app.start(attach, repository_privacy_context=_REPOSITORY)
        assert recovered.task_id == delegated.attach_handle.task_id
        handle = await store.get_handle(operation.handle_digest)
        assert handle is not None and handle.consumed_session_id == recovered.session_id
        routes = await catalog.recovery_routes()
        assert tuple(route.task_id for route in routes) == tuple(
            route.task_id for route in routes_after_crash
        )
        child = await store.get_task(recovered.task_id)
        assert child is not None and child.active_session_id == recovered.session_id

        # Recovery does not weaken the consumed contract afterwards.
        again = await service.app.start(attach, repository_privacy_context=_REPOSITORY)
        assert (again.task_id, again.session_id, again.writer_id) == (
            recovered.task_id,
            recovered.session_id,
            recovered.writer_id,
        )


@pytest.mark.parametrize("ref_kind", ("forged", "dangling", "quarantined"))
async def test_parent_reference_failures_are_typed_and_do_not_mint_children(
    tmp_path: Path,
    ref_kind: str,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        if ref_kind == "forged":
            parent_session_id = new_id(IdKind.SESSION)
        elif ref_kind == "dangling":
            parent = await app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create",
                        "task_title": "dangling parent",
                        "workspace_ref": str(workspace),
                        "external_ref": "dangling-parent",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            rotated = await app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create_or_attach",
                        "task_title": "dangling parent",
                        "workspace_ref": str(workspace),
                        "external_ref": "dangling-parent",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            assert rotated.task_id == parent.task_id
            assert rotated.session_id != parent.session_id
            parent_session_id = parent.session_id
        else:
            command_request = StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "quarantined parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "quarantined-parent",
                    "requested_view": "compact",
                }
            )
            command = await start_module._command(  # pyright: ignore[reportPrivateUsage]
                app, command_request, _REPOSITORY.commitment
            )
            allocation = await app.start_catalog.reserve_or_resume(command)
            assert allocation.phase is StartPhase.ROUTE_RESERVED
            await app.start_catalog.quarantine(allocation, SafeReason("start_route_contradiction"))
            parent_session_id = allocation.session_id

        with pytest.raises(PublicOperationError) as refused:
            await app.start(
                _delegate_request(parent_session_id, title=f"{ref_kind} child"),
                repository_privacy_context=_REPOSITORY,
            )
        assert refused.value.code is PublicErrorCode.SESSION_NOT_FOUND
        assert refused.value.safe_details["reason_code"] == "lineage_parent_not_found"
        lineage = app.lineage
        assert lineage is not None
        assert await cast(SqliteLineageStore, lineage.store).list_operations() == ()
