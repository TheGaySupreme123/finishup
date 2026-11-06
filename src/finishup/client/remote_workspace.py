"""How a client names its workspace to a remote server, and what answers for it (ADR-051).

The server-native network API binds a request to a workspace by the ``X-FinishUP-Workspace-Claim``
header and reaches the workspace through a pull-based workspace agent (``finishup agent run``).
Both pieces come from the shared client side of workspace remoting:

* the claim — ``finishup.client.workspace_claim.workspace_claim(locator, salt)`` under the
  target's ``claim_salt``;
* the handler — ``finishup.client.workspace_agent.WorkspaceAgentHandler(locator)``, which answers
  each ``workspace_call`` with the real local adapters and their fences.

This module is the one place this transport asks for them. No path is ever sent: a locator stays
on this machine, and only the keyed claim travels.
"""

from __future__ import annotations

from typing import Protocol

from finishup.client.targets import ServerTarget
from finishup.ports.control import (
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)

__all__ = ["WorkspaceCallHandler", "claim_for_workspace", "handler_for_workspace"]


class WorkspaceCallHandler(Protocol):
    """What answers ``workspace_call`` frames for one claimed workspace.

    ``answer`` runs in a worker thread, never on the event loop, and returns the reply to the call
    it was given; it should never raise.
    """

    @property
    def declaration(self) -> WorkspaceAgentDeclaration: ...

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply: ...


async def claim_for_workspace(
    record: ServerTarget, locator: WorkspaceLocator
) -> WorkspaceClaim | None:
    """The keyed claim on ``locator`` for ``record``'s server, or ``None`` when none can be made.

    INTEGRATION POINT — wired after split/client and split/server merge: decode
    ``record.claim_salt`` (base64, 32 bytes) and return
    ``await finishup.client.workspace_claim.workspace_claim(locator, salt)``; a locator the shared
    canonical-root rule cannot resolve returns ``None`` (the request then carries no claim and
    never a path). Until then no claim is made, so remote requests bind no workspace.
    """

    del record, locator
    return None


def handler_for_workspace(locator: WorkspaceLocator) -> WorkspaceCallHandler | None:
    """The handler that answers the server's workspace calls for ``locator``, or ``None``.

    INTEGRATION POINT — wired after split/client and split/server merge: return
    ``finishup.client.workspace_agent.WorkspaceAgentHandler(locator)``. Until then the workspace
    agent registers nothing and the server's calls end ``workspace_agent_unavailable``.
    """

    del locator
    return None
