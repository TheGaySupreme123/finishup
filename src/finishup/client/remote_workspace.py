"""How the network API's workspace agent names a workspace, answers for it, and delivers its rows.

The server-native network API binds a request to a workspace by the ``X-FinishUP-Workspace-Claim``
header and reaches the workspace through a pull-based workspace agent (``finishup agent run``,
ADR-051). Every piece comes from the shared client side of workspace remoting:

* the claim — ``finishup.client.workspace_claim.workspace_claim(locator, salt)`` under the
  target's own ``claim_salt``;
* the handler — ``finishup.client.workspace_agent.WorkspaceAgentHandler(locator)``, which answers
  each ``workspace_call`` with the real local adapters and their fences;
* the delivery of captured observation — ``ClientObservationDrain`` over a claim-bound
  ``RestServiceClient``, which attests each row from this client's own store (decision 12).

This module is the one place the agent asks for them. No path is ever sent: a locator stays on
this machine, and only the keyed claim travels.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

from finishup.client.targets import ServerTarget, TargetError
from finishup.observability.logging import record_bounded_event_without_raising
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)

if TYPE_CHECKING:
    from finishup.client.observation_outbox import ClientDrainSummary
    from finishup.domain.values import JsonObject

__all__ = [
    "CapturedObservationDelivery",
    "DeliveryClient",
    "DeliveryConnector",
    "WorkspaceCallHandler",
    "claim_for_workspace",
    "claim_salt",
    "handler_for_workspace",
]

_COMPONENT: Final = "client.agent"


class WorkspaceCallHandler(Protocol):
    """What answers ``workspace_call`` frames for one claimed workspace.

    ``answer`` runs in a worker thread, never on the event loop, and returns the reply to the call
    it was given; it should never raise.
    """

    @property
    def declaration(self) -> WorkspaceAgentDeclaration: ...

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply: ...


class DeliveryClient(Protocol):
    """A claim-bound client the delivery sends rows over (``RestServiceClient``).

    ``workspace_handle`` is what attests each row (``attest_for_connection``); without a valid
    ``client:`` handle the rows go unattested and the server refuses them, so they stay pending.
    """

    @property
    def workspace_handle(self) -> str | None: ...

    async def observation_ingest(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject: ...

    async def close(self) -> None: ...


type DeliveryConnector = Callable[[WorkspaceClaim], Awaitable[DeliveryClient]]


def claim_salt(record: ServerTarget) -> bytes:
    """The target's 32-byte ``claim_salt``; an unusable record fails closed."""

    raw = record.claim_salt
    if type(raw) is not str:
        raise TargetError("target_record_invalid")
    try:
        return base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error):
        raise TargetError("target_record_invalid") from None


async def claim_for_workspace(
    record: ServerTarget, locator: WorkspaceLocator
) -> WorkspaceClaim | None:
    """The keyed claim on ``locator`` for ``record``'s server, or ``None`` when none can be made.

    The claim is ``workspace_claim(locator, salt)`` under the target's own salt — the same claim a
    client process sends for the same workspace, so the agent and the client bind one handle. A
    locator the shared canonical-root rule cannot resolve returns ``None``: nothing then answers
    for it, and the server's calls for it end ``workspace_agent_unavailable``, never a path.
    """

    from finishup.adapters.workspace_root import RepositoryIdentityError
    from finishup.client.workspace_claim import workspace_claim

    salt = claim_salt(record)
    try:
        return await workspace_claim(locator, salt)
    except RepositoryIdentityError:
        return None


def handler_for_workspace(locator: WorkspaceLocator, root: Path) -> WorkspaceCallHandler | None:
    """The handler that answers the server's workspace calls for ``locator``.

    ``WorkspaceAgentHandler`` runs each call on the real local adapters, confined to this one
    claimed workspace and the admitted roots the server names. Besides the directories every
    handler protects (this process's own FinishUP directories and the everyday installation's),
    the target root itself is protected: it holds this client's credential and outbox.
    """

    import os

    from finishup.client.workspace_agent import WorkspaceAgentHandler, client_protected_directories

    protected = (*client_protected_directories(), os.path.normpath(os.fspath(root)))
    return WorkspaceAgentHandler(locator, protected=tuple(dict.fromkeys(protected)))


async def _rest_delivery_client(
    record: ServerTarget, root: Path, claim: WorkspaceClaim
) -> DeliveryClient:
    from finishup.client.rest_client import connect_rest_service

    return await connect_rest_service(ControlClientKind.CLI, record=record, root=root, claim=claim)


class CapturedObservationDelivery:
    """Deliver one claimed workspace's captured observation to the target's server.

    Hooks deliver what they can on each pass; this delivers the rest in the background, one
    bounded ``ClientObservationDrain`` pass per call, over one claim-bound ``RestServiceClient``
    kept between passes (``GET /v1/server`` once, not per pass). A pass that stopped at a control
    failure closes that client, and the next pass connects again. The rows' store is the target
    root's own (``<root>/state``), whichever root this process itself resolves.
    """

    __slots__ = ("_claim", "_client", "_connect", "_drain")

    def __init__(
        self,
        record: ServerTarget,
        root: Path,
        locator: WorkspaceLocator,
        claim: WorkspaceClaim,
        *,
        connect: DeliveryConnector | None = None,
    ) -> None:
        from finishup.client.observation_outbox import ClientObservationDrain

        if type(claim) is not WorkspaceClaim:
            raise TypeError("workspace_claim_invalid")
        self._claim = claim
        self._connect: DeliveryConnector = connect or (
            lambda value: _rest_delivery_client(record, root, value)
        )
        self._drain = ClientObservationDrain(locator, state=root / "state")
        self._client: DeliveryClient | None = None

    async def deliver(self) -> ClientDrainSummary | None:
        """One pass; ``None`` when the server could not be reached for it (the rows stay)."""

        client = self._client
        if client is None:
            try:
                client = await self._connect(self._claim)
            except ControlError as error:
                record_bounded_event_without_raising(
                    component=_COMPONENT,
                    operation="workspace_agent_drain",
                    reason=error.phase or error.reason,
                )
                return None
            self._client = client
        summary = await self._drain.drain(client)
        if summary.stopped is not None:
            record_bounded_event_without_raising(
                component=_COMPONENT, operation="workspace_agent_drain", reason=summary.stopped
            )
            await self._release()
        return summary

    async def _release(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()

    async def close(self) -> None:
        await self._release()
        self._drain.close()
