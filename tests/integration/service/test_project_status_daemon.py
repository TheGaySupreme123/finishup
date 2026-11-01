"""Project status through the real service daemon after member receipts (#840).

The application-level conformance cases prove the projection and the stage classification. This
file proves the service boundary around them: the privacy projection, the agent (MCP) summary, and
the human CLI rendering all carry member receipts, and a classified status fault reaches the wire
with the correlation id the application recorded, so the daemon mints no second, class-free
``status_public_error`` record.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.application.status as status_module
from builders.multi_agent import INSTANCE_ID, MultiAgentService, multi_agent_service
from conformance.observation.test_project_status_faults import (
    _REPOSITORY,  # pyright: ignore[reportPrivateUsage]
    _two_roots_with_receipts,  # pyright: ignore[reportPrivateUsage]
    _workspace,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.service import ClientProjectionContext
from finishup.application.start import StartInternalResult
from finishup.cli.render import render_human_status
from finishup.mcp.summaries import summary_for_public_error, summary_for_status
from finishup.observability.diagnostics import lookup_diagnostic_records
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlMethod,
    ProjectionRenderMode,
)
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    StatusProjectPageModel,
    StatusRequest,
    StatusResult,
    StatusSuccessModel,
)
from finishup.service.daemon import ServiceComposition, ServiceDaemon
from finishup.service.lifecycle import ServiceLifecycle

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Clock:
    instant: datetime = datetime(2026, 9, 25, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.instant

    def monotonic_seconds(self) -> float:
        return self.instant.timestamp()


class _Generations:
    def advance(self, instance_id: str) -> int:
        assert instance_id == INSTANCE_ID
        return 1


class _Listener:
    def __init__(self) -> None:
        self._closed = asyncio.Event()

    async def accept(self) -> object:
        await self._closed.wait()
        raise RuntimeError("closed")

    async def aclose(self) -> None:
        self._closed.set()


class _Monitor:
    class _Capability:
        active = False

    capability = _Capability()

    async def start(self, callback: object) -> None:
        del callback

    async def close(self) -> None:
        return None


def _daemon(service: MultiAgentService, root: Path) -> ServiceDaemon:
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_Generations(),
        process_start_identity_commitment="sha256:" + "e" * 64,
        instance_id=INSTANCE_ID,
        singleton_lock_path=root / "daemon.lock",
    )
    return ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=_Monitor(),  # pyright: ignore[reportArgumentType]
            vault=service.vault,  # pyright: ignore[reportArgumentType]
            application=cast(Any, service.app),
        )
    )


def _status_call(
    daemon: ServiceDaemon, task: StartInternalResult, request_id: str
) -> ControlCallRequest:
    instance = daemon.composition.lifecycle.instance
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=instance.instance_id,
        service_generation=str(instance.generation),
        method=ControlMethod.STATUS,
        body=StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": request_id,
                "actor": {"actor_id": "harness:project-status-daemon", "actor_type": "harness"},
                "client": {
                    "kind": "cooperative_agent",
                    "version": "0.3.0",
                    "integration": "cooperative_mcp",
                },
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "view": "project",
                "limit": "100",
            }
        ),
    )


async def test_daemon_projects_member_receipts_for_agent_and_human_sinks(tmp_path: Path) -> None:
    async with multi_agent_service(tmp_path / "state") as service:
        first, second, project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        daemon = _daemon(service, tmp_path)
        await daemon.start()
        try:
            for client_kind, context in (
                (
                    ControlClientKind.MCP_BRIDGE,
                    ClientProjectionContext.fail_safe(ControlClientKind.MCP_BRIDGE),
                ),
                (
                    ControlClientKind.CLI,
                    ClientProjectionContext(
                        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True
                    ),
                ),
            ):
                result = await daemon.dispatch(
                    client_kind,
                    _status_call(daemon, first.task, new_id(IdKind.REQUEST)),
                    projection_context=context,
                    repository_privacy_context=_REPOSITORY,
                )
                assert result.outcome == "ok"
                body = result.body
                assert isinstance(body, StatusResult)
                success = body.root
                assert isinstance(success, StatusSuccessModel)
                page = success.page
                assert isinstance(page, StatusProjectPageModel)
                assert page.project_id == project_id
                assert {item.task_id for item in page.receipts} == {
                    first.task.task_id,
                    second.task.task_id,
                }
                if client_kind is ControlClientKind.MCP_BRIDGE:
                    summary = summary_for_status(success.model_dump(mode="json"))
                    assert "receipts: 2" in summary
                    assert "detections: 1" in summary
                else:
                    rendered = render_human_status(success)
                    assert "Member receipts:" in rendered
                    for root in (first, second):
                        assert root.receipt.receipt_id in rendered
        finally:
            await daemon.close()


async def test_daemon_returns_the_application_correlation_for_a_classified_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        daemon = _daemon(service, tmp_path)
        await daemon.start()

        def faulty_digest(value: object) -> str:
            del value
            raise ValueError("canary-840-daemon")

        monkeypatch.setattr(status_module, "canonical_digest", faulty_digest)
        request_id = new_id(IdKind.REQUEST)
        try:
            result = await daemon.dispatch(
                ControlClientKind.MCP_BRIDGE,
                _status_call(daemon, first.task, request_id),
                repository_privacy_context=_REPOSITORY,
            )
        finally:
            await daemon.close()
        assert result.outcome == "ok"
        body = result.body
        assert isinstance(body, StatusResult)
        failure = body.root.model_dump(mode="json")
        assert failure["ok"] is False
        error = cast(dict[str, object], failure["error"])
        assert error["code"] == PublicErrorCode.INTERNAL_ERROR.value
        assert error["retryable"] is False
        correlation_id = error["correlation_id"]
        assert type(correlation_id) is str
        (record,) = lookup_diagnostic_records(correlation_id)
        assert record["component"] == "application.status"
        assert record["operation"] == "status_project_digest_failed"
        assert record["reason"] == "exception_value_error"
        assert record["request_id"] == request_id
        origin = record["origin"]
        assert type(origin) is str and origin.startswith("finishup.application.status:")
        # One failure, one id: the daemon reused the classified id instead of minting a
        # class-free ``status_public_error`` record beside it.
        joined = lookup_diagnostic_records(request_id=request_id)
        assert [item["correlation_id"] for item in joined] == [correlation_id]
        assert "canary-840-daemon" not in repr(joined)
        summary = summary_for_public_error(failure)
        assert "Error INTERNAL_ERROR; retryable: no" in summary
        assert correlation_id in summary
