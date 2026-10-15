"""MCP bridge maps each receipt projection failure to its own actionable public error."""

from __future__ import annotations

from typing import cast

import pytest

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_control_error_blocked_is_privacy_authority_required() -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("privacy_projection_blocked", retryable=False),
        request_id="req_00000000-0000-4000-8000-000000000001",
        operation="receipt",
    )
    assert result.isError is True
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED.value
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "receipt_json_projection_blocked"
    message = cast(str, error["message"]).lower()
    assert "markdown" in message or "text" in message


def test_control_error_unavailable_is_retryable_service_unavailable() -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("privacy_projection_unavailable", retryable=True),
        request_id="req_00000000-0000-4000-8000-000000000002",
        operation="receipt",
    )
    assert result.isError is True
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "privacy_projection_unavailable"
