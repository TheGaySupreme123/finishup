"""A start over a claim-bound connection names its workspace by the handle, never a path."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from finishup.client.workspace_ref import (
    WorkspaceRefNotPortable,
    portable_start_request,
    portable_workspace_ref,
    start_request_for_connection,
)
from finishup.ports.control import ControlError, WorkspaceBinding
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.models import StartRequest, public_model_to_wire

_HANDLE = "client:0123456789abcdef"
_PATH = "/srv/dev/private-project"


def _start(workspace_ref: str | None = _PATH) -> StartRequest:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000041",
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create_or_attach",
        "task_title": "Remote task",
        "requested_view": "compact",
    }
    if workspace_ref is not None:
        # The start contract pairs the two references: both or neither.
        body["workspace_ref"] = workspace_ref
        body["external_ref"] = "host-session:1"
    return StartRequest.model_validate(body)


@pytest.mark.parametrize("binding", ["none", "local_path"])
def test_a_local_or_unbound_connection_sends_the_ref_as_written(binding: str) -> None:
    for value in (_PATH, "label", None):
        assert (
            portable_workspace_ref(
                value, workspace_binding=cast(WorkspaceBinding, binding), workspace_handle=None
            )
            == value
        )
    request = _start()
    assert (
        portable_start_request(
            request, workspace_binding=cast(WorkspaceBinding, binding), workspace_handle=_HANDLE
        )
        is request
    )


def test_a_claim_bound_connection_sends_its_handle_for_a_path() -> None:
    assert (
        portable_workspace_ref(_PATH, workspace_binding="client_claim", workspace_handle=_HANDLE)
        == _HANDLE
    )
    # A ref that is no path, or none at all, is left for the server to judge.
    for value in ("label", _HANDLE, None):
        assert (
            portable_workspace_ref(
                value, workspace_binding="client_claim", workspace_handle=_HANDLE
            )
            == value
        )


def test_the_rewritten_request_differs_only_in_its_workspace_ref() -> None:
    request = _start()
    portable = portable_start_request(
        request, workspace_binding="client_claim", workspace_handle=_HANDLE
    )
    assert type(portable) is StartRequest and portable is not request
    before, after = public_model_to_wire(request), public_model_to_wire(portable)
    assert after.pop("workspace_ref") == _HANDLE
    assert before.pop("workspace_ref") == _PATH
    assert after == before
    assert _PATH not in repr(public_model_to_wire(portable))
    unchanged = _start(None)
    assert (
        portable_start_request(
            unchanged, workspace_binding="client_claim", workspace_handle=_HANDLE
        )
        is unchanged
    )


@pytest.mark.parametrize("handle", [None, "client:XYZ", "/srv/dev/private-project"])
@pytest.mark.parametrize("workspace_ref", [_PATH, None, "label"])
def test_no_handle_means_nothing_is_sent_and_the_locked_vault_is_named(
    handle: str | None, workspace_ref: str | None
) -> None:
    """ADR-051: the server keys a claim only while its vault is ready; with no handle no start
    is sent, whether it names a path or no workspace at all (which the server would open on the
    handle it could not give), and the refusal is the server's own retryable ``vault_locked``."""

    with pytest.raises(ControlError) as raised:
        portable_workspace_ref(
            workspace_ref, workspace_binding="client_claim", workspace_handle=handle
        )
    assert (raised.value.reason, raised.value.retryable) == ("vault_locked", True)
    assert "private-project" not in repr(raised.value)
    with pytest.raises(ControlError) as raised:
        portable_start_request(
            _start(workspace_ref), workspace_binding="client_claim", workspace_handle=handle
        )
    assert raised.value.reason == "vault_locked"


def test_the_not_portable_refusal_keeps_its_fixed_shape() -> None:
    refusal = WorkspaceRefNotPortable()
    assert refusal.code is PublicErrorCode.INVALID_REQUEST
    assert refusal.retryable is False
    assert dict(refusal.safe_details) == {
        "continuation": "workspace_handle_required",
        "reason_code": "workspace_ref_not_portable",
    }


def test_an_unknown_binding_is_a_caller_defect() -> None:
    with pytest.raises(ValueError, match="workspace_binding_invalid"):
        portable_workspace_ref(
            _PATH, workspace_binding=cast(WorkspaceBinding, "remote"), workspace_handle=_HANDLE
        )
    with pytest.raises(TypeError, match="start_request_invalid"):
        portable_start_request(
            cast(StartRequest, object()), workspace_binding="none", workspace_handle=None
        )


def test_the_connection_supplies_its_binding_and_handle() -> None:
    request = _start()
    bound = SimpleNamespace(workspace_binding="client_claim", workspace_handle=_HANDLE)
    assert start_request_for_connection(request, bound).workspace_ref == _HANDLE
    # A connection that reports no binding, or an unreadable one, sends the request as written.
    for connection in (
        object(),
        SimpleNamespace(workspace_binding="local_path", workspace_handle=None),
        SimpleNamespace(workspace_binding=object(), workspace_handle=_HANDLE),
    ):
        assert start_request_for_connection(request, connection) is request
    with pytest.raises(ControlError) as raised:
        start_request_for_connection(
            request, SimpleNamespace(workspace_binding="client_claim", workspace_handle=None)
        )
    assert raised.value.reason == "vault_locked"
