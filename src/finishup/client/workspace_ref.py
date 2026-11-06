"""Name a task's workspace by its handle on a claim-bound connection (ADR-051).

A FinishUP server on another machine cannot read paths on this one, and the client never sends it
one: a ``start`` whose ``workspace_ref`` is an absolute path is rewritten, just before it is sent,
to the ``client:`` handle the server answered this connection's hello with. That handle is
derived from the connection's workspace claim, so every start through the same claim names the
same workspace and attach finds the task again. A connection bound by a local path, or not bound
at all, sends the request exactly as written, as does a ``workspace_ref`` that is no path.

A start that names no workspace goes as written too: the server opens it on the connection's
handle. A claim-bound connection with no handle exists for one reason: the server's vault was not
ready when the connection said hello, so the server could not key the claim. No start is sent on
it, whatever its ``workspace_ref``; the refusal is the retryable ``vault_locked`` the server
itself would give, so a caller discards that connection and the first call after the unlock opens
a fresh one that gets a handle.
"""

from __future__ import annotations

from typing import Final, cast

from finishup.ports.control import WORKSPACE_BINDINGS, ControlError, WorkspaceBinding
from finishup.ports.workspace_agent import workspace_handle_valid
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StartRequest, public_model_to_wire

__all__ = [
    "WorkspaceRefNotPortable",
    "portable_start_request",
    "portable_workspace_ref",
    "start_request_for_connection",
]

_NOT_PORTABLE_MESSAGE: Final = (
    "The selected FinishUP server is on another machine and gave this connection no workspace "
    "handle, so a start naming a workspace path was not sent."
)


class WorkspaceRefNotPortable(PublicOperationError):
    """A start would have sent a path to a server on another machine; nothing was sent.

    The message and details are fixed; neither names the path. A claim-bound connection without
    a handle raises the retryable ``vault_locked`` ``ControlError`` instead (see the module).
    """

    def __init__(self) -> None:
        super().__init__(
            PublicErrorCode.INVALID_REQUEST,
            _NOT_PORTABLE_MESSAGE,
            False,
            safe_details={"reason_code": "workspace_ref_not_portable"},
        )


def portable_workspace_ref(
    workspace_ref: str | None,
    *,
    workspace_binding: WorkspaceBinding,
    workspace_handle: str | None,
) -> str | None:
    """The ``workspace_ref`` to send: the handle in place of an absolute path when claim-bound."""

    if workspace_binding not in WORKSPACE_BINDINGS:
        raise ValueError("workspace_binding_invalid")
    if workspace_binding != "client_claim":
        return workspace_ref
    if not workspace_handle_valid(workspace_handle):
        # The server could not key this connection's claim at hello: its vault was not ready.
        # No start is sent, whether it names a path or no workspace at all (which the server
        # opens on the handle it could not give), and the caller replaces the connection once
        # the vault is unlocked.
        raise ControlError("vault_locked", retryable=True)
    if workspace_ref is None or not workspace_ref.startswith("/"):
        return workspace_ref
    return workspace_handle


def portable_start_request(
    request: StartRequest,
    *,
    workspace_binding: WorkspaceBinding,
    workspace_handle: str | None,
) -> StartRequest:
    """``request`` itself, or the same request naming its workspace by the connection's handle."""

    if type(request) is not StartRequest:
        raise TypeError("start_request_invalid")
    workspace_ref = portable_workspace_ref(
        request.workspace_ref,
        workspace_binding=workspace_binding,
        workspace_handle=workspace_handle,
    )
    if workspace_ref == request.workspace_ref:
        return request
    wire = public_model_to_wire(request)
    wire["workspace_ref"] = workspace_ref
    return StartRequest.model_validate(wire)


def start_request_for_connection(request: StartRequest, connection: object) -> StartRequest:
    """``portable_start_request`` for the connection about to send ``request``.

    The binding and handle are the ones ``ServiceClient`` reports from its hello. A connection that
    reports none (a stand-in, or a client older than workspace binding) is treated as unbound, so
    the request goes out as written, exactly as before.
    """

    binding = getattr(connection, "workspace_binding", "none")
    handle = getattr(connection, "workspace_handle", None)
    if type(binding) is not str or binding not in WORKSPACE_BINDINGS:
        binding = "none"
    return portable_start_request(
        request,
        workspace_binding=cast(WorkspaceBinding, binding),
        workspace_handle=handle if type(handle) is str else None,
    )
