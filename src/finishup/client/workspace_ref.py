"""Name a task's workspace by its handle on a claim-bound connection (ADR-051).

A FinishUP server on another machine cannot read paths on this one, and the client never sends it
one: a ``start`` whose ``workspace_ref`` is an absolute path is rewritten, just before it is sent,
to the ``client:`` handle the server answered this connection's hello with. That handle is
derived from the connection's workspace claim, so every start through the same claim names the
same workspace and attach finds the task again. A local connection bound by a path, or not bound
at all, sends the request exactly as written, as does a ``workspace_ref`` that is no path; a
connection to another machine that claimed no workspace refuses an absolute path instead.
"""

from __future__ import annotations

from typing import Final, cast

from finishup.ports.control import (
    WORKSPACE_BINDINGS,
    ControlError,
    ServiceState,
    ServiceStatus,
    WorkspaceBinding,
)
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

    Raised only when a claim-bound connection has no handle to send instead. The message and
    details are fixed; neither names the path.
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
    remote: bool = False,
) -> str | None:
    """The ``workspace_ref`` to send: the handle in place of an absolute path when claim-bound.

    ``remote`` marks a connection to a server on another machine whatever its binding: one that
    claimed no workspace has no handle, so an absolute path is refused rather than sent.
    """

    if workspace_binding not in WORKSPACE_BINDINGS:
        raise ValueError("workspace_binding_invalid")
    if workspace_ref is None or (workspace_binding != "client_claim" and not remote):
        return workspace_ref
    if not workspace_ref.startswith("/"):
        return workspace_ref
    if not workspace_handle_valid(workspace_handle):
        raise WorkspaceRefNotPortable()
    return workspace_handle


def portable_start_request(
    request: StartRequest,
    *,
    workspace_binding: WorkspaceBinding,
    workspace_handle: str | None,
    remote: bool = False,
) -> StartRequest:
    """``request`` itself, or the same request naming its workspace by the connection's handle."""

    if type(request) is not StartRequest:
        raise TypeError("start_request_invalid")
    workspace_ref = portable_workspace_ref(
        request.workspace_ref,
        workspace_binding=workspace_binding,
        workspace_handle=workspace_handle,
        remote=remote,
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
    the request goes out as written, exactly as before. A connection whose ``transport`` is not
    the local ``unix`` endpoint reaches a server on another machine: unbound or not, it never
    carries an absolute path.

    A server whose vault is locked binds no handle, so the path could not be sent for that
    reason alone: when the connection's hello says the service is locked, the refusal is the
    service's own ``vault_locked`` (each surface then names the remote unlock), not a missing
    handle. Nothing is sent either way.
    """

    binding = getattr(connection, "workspace_binding", "none")
    handle = getattr(connection, "workspace_handle", None)
    transport = getattr(connection, "transport", "unix")
    if type(binding) is not str or binding not in WORKSPACE_BINDINGS:
        binding = "none"
    try:
        return portable_start_request(
            request,
            workspace_binding=cast(WorkspaceBinding, binding),
            workspace_handle=handle if type(handle) is str else None,
            remote=type(transport) is str and transport != "unix",
        )
    except WorkspaceRefNotPortable:
        status = getattr(connection, "hello_service_status", None)
        if type(status) is ServiceStatus and status.state is ServiceState.LOCKED:
            raise ControlError("vault_locked") from None
        raise
