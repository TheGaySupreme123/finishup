"""MCP names a folder refusal by its closed token and remedy, never as an absent service (ADR-048)."""

from __future__ import annotations

from typing import cast

import pytest

import finishup.mcp.server as bridge
from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.cli.exits import remediation_message
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode
from finishup.service import client as client_module


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    return cast(dict[str, object], structured["error"])


@pytest.mark.parametrize(
    "reason",
    ["installation_root_ambiguous", "isolation_root_env_conflict", "permissions_too_broad"],
)
def test_a_folder_refusal_is_storage_unsafe_with_its_token_and_remedy(reason: str) -> None:
    refused = client_module._transport_error(  # pyright: ignore[reportPrivateUsage]
        LocalControlTransportError("runtime_directory_unsafe", path_reason=reason)
    )

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        refused,
        request_id="req_00000000-0000-4000-8000-000000000001",
        operation="status",
    )

    assert result.isError is True
    error = _error(result)
    assert error["code"] == PublicErrorCode.STORAGE_UNSAFE.value
    assert error["retryable"] is False
    message = cast(str, error["message"])
    assert f"FinishUP's local folders cannot be used safely ({reason})" in message
    remedy = remediation_message(reason)
    assert remedy is not None
    assert message.endswith(remedy)
    assert "/home/" not in message
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "endpoint_unsafe"


def test_a_plain_unsafe_endpoint_keeps_its_endpoint_wording() -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("endpoint_unsafe"),
        request_id="req_00000000-0000-4000-8000-000000000002",
        operation="status",
    )

    error = _error(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert "local folders" not in cast(str, error["message"])
