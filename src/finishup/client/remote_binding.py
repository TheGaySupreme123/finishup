"""The workspace binding a connection to a FinishUP server on another machine sends (ADR-051).

One call composes the pieces: the claim on the workspace under the target's own salt, and,
when the connection is to answer the server's workspace calls, the agent for that workspace.
Whether a root is remote, and which salt it keeps, are the caller's to decide (the selected
target's ``target.json``); a local root sends its locator exactly as before and needs none of
this. The agent's adapters load only when an agent is asked for, so a connection that only
claims (a short-lived hook, say) stays light.
"""

from __future__ import annotations

from collections.abc import Sequence

from finishup.client.workspace_claim import workspace_claim
from finishup.ports.control import WorkspaceLocator
from finishup.service.client import ClientWorkspaceBinding

__all__ = ["remote_workspace_binding"]


async def remote_workspace_binding(
    workspace: WorkspaceLocator,
    claim_salt: bytes,
    *,
    serve_workspace: bool = True,
    protected: Sequence[str] | None = None,
) -> ClientWorkspaceBinding:
    """The claim on ``workspace`` under ``claim_salt``, with its agent when ``serve_workspace``.

    ``protected`` is passed to the agent (``WorkspaceAgentHandler``); by default it protects
    this client's own FinishUP directories. A locator the shared root rule cannot resolve raises
    its closed ``RepositoryIdentityError``; the caller must then not connect with a path instead.
    """

    claim = await workspace_claim(workspace, claim_salt)
    if not serve_workspace:
        return ClientWorkspaceBinding(claim)
    from finishup.client.workspace_agent import WorkspaceAgentHandler

    return ClientWorkspaceBinding(claim, WorkspaceAgentHandler(workspace, protected=protected))
