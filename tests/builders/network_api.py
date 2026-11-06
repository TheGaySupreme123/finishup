"""Fakes for the server-native network API (ADR-051): a service, a claim resolver, an agent hub.

``FakeService`` stands in for the daemon behind ``NetworkApiBindings``: it answers
``service_status`` with a fixed status and every other method with a canned body, recording each
dispatch; ``FakeHub`` has the ``WorkspaceAgentHub`` registration surface and a ``call`` that sends
one ``workspace_call`` through a registered channel's writer and awaits its reply.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import tempfile
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service.api_keys import ApiKeyStore
from finishup.service.http_api import NetworkApi, NetworkApiBindings

__all__ = [
    "INSTANCE_ID",
    "FakeHub",
    "FakeService",
    "claim",
    "context_for",
    "key_store",
    "make_api",
    "service_status",
]

INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"


def service_status(generation: str = "7") -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id=INSTANCE_ID,
        service_generation=generation,
        state=ServiceState.READY,
        state_reason="none",
        vault_mode="os_keyring",
        capabilities=(),
        session_monitor="active",
    )


def claim(seed: str = "a") -> WorkspaceClaim:
    return WorkspaceClaim("git_common_root", "sha256:" + hashlib.sha256(seed.encode()).hexdigest())


def context_for(workspace_claim: WorkspaceClaim) -> RepositoryPrivacyContext:
    """What a claim resolver answers: a ``client_claim`` commitment derived from the digest."""

    digest = hashlib.sha256(workspace_claim.digest.encode("ascii")).hexdigest()
    return RepositoryPrivacyContext("hmac-sha256:" + digest, "client_claim")


type _Dispatched = tuple[ControlClientKind, ControlCallRequest, RepositoryPrivacyContext | None]


@dataclass
class FakeService:
    """The daemon side of the bindings: status, dispatch and an idle-hold counter."""

    generation: str = "7"
    delay: float = 0.0
    seen: list[_Dispatched] = field(default_factory=lambda: list[_Dispatched]())
    active: int = 0
    gate: asyncio.Event | None = None

    def status(self) -> ServiceStatus:
        return service_status(self.generation)

    async def dispatch(
        self,
        client_kind: ControlClientKind,
        request: ControlCallRequest,
        context: RepositoryPrivacyContext | None,
    ) -> ControlResult:
        self.seen.append((client_kind, request, context))
        if request.service_generation != self.generation:
            body: object = ControlError("service_generation_changed", retryable=True)
            outcome = "error"
        else:
            if self.gate is not None:
                await self.gate.wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            outcome = "ok"
            if request.method is ControlMethod.SERVICE_STATUS:
                body = self.status()
            elif request.method is ControlMethod.SERVICE_LOCK:
                body = replace(
                    self.status(), state=ServiceState.LOCKED, state_reason="explicit_lock"
                )
            else:
                body = JsonObject({"echo": request.method.value})
        return ControlResult(
            protocol_version="1.0",
            rpc_id=request.rpc_id,
            service_instance_id=request.service_instance_id,
            service_generation=request.service_generation,
            method=request.method,
            outcome=outcome,  # type: ignore[arg-type]
            body=body,  # type: ignore[arg-type]
        )

    @contextlib.asynccontextmanager
    async def activity(self) -> AsyncGenerator[None]:
        self.active += 1
        try:
            yield
        finally:
            self.active -= 1


@dataclass
class _Channel:
    handle: str
    declaration: WorkspaceAgentDeclaration
    writer: Callable[[WorkspaceCall], Awaitable[None]]
    pending: dict[str, asyncio.Future[WorkspaceReply]] = field(
        default_factory=lambda: dict[str, asyncio.Future[WorkspaceReply]]()
    )
    closed: bool = False


class FakeHub:
    """The ``WorkspaceAgentHub`` registration surface, and one way to call an agent."""

    def __init__(self) -> None:
        self.channels: list[_Channel] = []
        self.delivered: list[WorkspaceReply] = []

    async def register(
        self,
        *,
        handle: str,
        declaration: WorkspaceAgentDeclaration,
        service_instance_id: str,
        service_generation: str,
        writer: Callable[[WorkspaceCall], Awaitable[None]],
    ) -> Any:
        del service_instance_id, service_generation
        channel = _Channel(handle, declaration, writer)
        self.channels.append(channel)
        return channel

    def deliver(self, channel: Any, reply: WorkspaceReply) -> None:
        self.delivered.append(reply)
        future = channel.pending.get(reply.call_id)
        if future is not None and not future.done():
            future.set_result(reply)

    async def unregister(self, channel: Any) -> None:
        channel.closed = True
        for future in channel.pending.values():
            if not future.done():
                future.set_exception(RuntimeError("agent_disconnected"))

    def live(self, handle: str) -> list[_Channel]:
        return [
            channel for channel in self.channels if channel.handle == handle and not channel.closed
        ]

    async def call(
        self, handle: str, operation: str, arguments: dict[str, Any], *, timeout: float = 5.0
    ) -> WorkspaceReply:
        deadline = asyncio.get_running_loop().time() + timeout
        while not self.live(handle):
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError("no_agent")
            await asyncio.sleep(0.01)
        channel = self.live(handle)[0]
        call = WorkspaceCall(
            kind="workspace_call",
            protocol_version="1.0",
            call_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=INSTANCE_ID,
            service_generation="7",
            operation=operation,
            arguments=JsonObject(arguments),
            deadline_ms=5_000,
        )
        future: asyncio.Future[WorkspaceReply] = asyncio.get_running_loop().create_future()
        channel.pending[call.call_id] = future
        await channel.writer(call)
        async with asyncio.timeout(timeout):
            return await future


def key_store(directory: Path | None = None) -> ApiKeyStore:
    base = directory or Path(tempfile.mkdtemp(prefix=".yz-keys-", dir=Path.home()))
    os.chmod(base, 0o700)
    return ApiKeyStore(base / "network")


def make_api(
    service: FakeService,
    keys: ApiKeyStore,
    *,
    hub: FakeHub | None = None,
    resolve: bool = True,
    clock: Callable[[], float] | None = None,
) -> NetworkApi:
    async def resolver(workspace_claim: WorkspaceClaim) -> RepositoryPrivacyContext | None:
        return context_for(workspace_claim)

    bindings = NetworkApiBindings(
        status=service.status,
        dispatch=service.dispatch,
        activity=service.activity,
        claim_resolver=resolver if resolve else None,
        agent_hub=hub,
    )
    if clock is None:
        return NetworkApi(bindings, keys)
    return NetworkApi(bindings, keys, clock=clock)
