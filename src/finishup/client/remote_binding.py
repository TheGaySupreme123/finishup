"""The workspace binding a connection to a FinishUP server on another machine sends (ADR-051).

One call composes the pieces: the claim on the workspace under the target's own salt, and,
when the connection is to answer the server's workspace calls, the agent for that workspace.
``binding_for_active_root`` decides from the root this process uses: a local root (the everyday
installation, an isolated root that is not a target, or a named local server) sends its locator
exactly as before and needs none of this; a remote root (``local_port``, ``ssh``, ``https``)
claims under the ``claim_salt`` its ``target.json`` keeps. The agent's adapters load only when an
agent is asked for, so a connection that only claims (a short-lived hook, say) stays light.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from typing import cast

from finishup.client.targets import TargetError, active_target_record
from finishup.client.workspace_claim import workspace_claim
from finishup.ports.control import WorkspaceLocator
from finishup.service.client import ClientWorkspaceBinding

__all__ = ["binding_for_active_root", "is_remote_active_root", "remote_workspace_binding"]


async def remote_workspace_binding(
    workspace: WorkspaceLocator,
    claim_salt: bytes,
    *,
    serve_workspace: bool = True,
    protected: Sequence[str] | None = None,
) -> ClientWorkspaceBinding:
    """The claim on ``workspace`` under ``claim_salt``, with its agent when ``serve_workspace``.

    ``protected`` is passed to the agent (``WorkspaceAgentHandler``); by default it protects
    this client's own FinishUP directories and the everyday installation's. A locator the shared
    root rule cannot resolve raises its closed ``RepositoryIdentityError``; the caller must then
    not connect with a path instead.
    """

    claim = await workspace_claim(workspace, claim_salt)
    if not serve_workspace:
        return ClientWorkspaceBinding(claim)
    from finishup.client.workspace_agent import WorkspaceAgentHandler

    return ClientWorkspaceBinding(claim, WorkspaceAgentHandler(workspace, protected=protected))


def is_remote_active_root() -> bool:
    """Whether the root this process uses is a FinishUP server on another machine.

    True when the selected (or explicitly isolated) root's ``target.json`` names a remote kind:
    ``local_port``, ``ssh`` or ``https``. False for the everyday installation, an isolated root
    that is not a target, and a named local server. A root or record that cannot be read fails
    closed with its closed ``TargetError``; it never reads as local.
    """

    record = active_target_record()
    return record is not None and record.is_remote


async def binding_for_active_root(
    locator: WorkspaceLocator | None, *, serve_workspace: bool
) -> ClientWorkspaceBinding | None:
    """The workspace binding a connection from this process sends, or None to send the locator.

    None for a local root: connect with ``workspace_locator=locator`` exactly as before. For a
    remote root, the claim on ``locator`` under the target's own ``claim_salt`` and, when
    ``serve_workspace``, the workspace agent that answers for it (``remote_workspace_binding``);
    connect with ``workspace_binding=`` that and no locator. A remote root with no workspace
    (``locator`` None) has nothing to claim and also returns None, so the connection sends
    neither. A path is never sent to a remote root either way.

    Fails closed: a root or record that cannot be read raises its ``TargetError``, and a locator
    the shared root rule cannot resolve raises ``RepositoryIdentityError``; the caller must not
    fall back to sending the locator.
    """

    record = active_target_record()
    if record is None or not record.is_remote or locator is None:
        return None
    try:
        salt = base64.b64decode(cast(str, record.claim_salt), validate=True)
    except (TypeError, ValueError, binascii.Error):
        raise TargetError("target_record_invalid") from None
    return await remote_workspace_binding(locator, salt, serve_workspace=serve_workspace)
