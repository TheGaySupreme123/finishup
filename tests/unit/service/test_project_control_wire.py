"""2.5 project-control errors remain typed on the ordinary control wire."""

from __future__ import annotations

import pytest

from finishup.domain.coordination import CoordinationErrorCode
from finishup.ports.control import ControlError, ControlMethod, ControlResult
from finishup.protocol.errors import PublicErrorCode
from finishup.service.control_protocol import (
    decode_control_frame,
    encode_control_frame,
    parse_control_result,
    public_error_code_for_control_reason,
    validate_result,
)

_RPC_ID = "rpc_69000000-0000-4000-8000-000000000001"
_SERVICE_ID = "svc_69000000-0000-4000-8000-000000000002"


def _project_error(reason: str) -> ControlResult:
    return ControlResult(
        protocol_version="1.0",
        rpc_id=_RPC_ID,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.PROJECT,
        outcome="error",
        body=ControlError(reason),
    )


@pytest.mark.parametrize("code", tuple(CoordinationErrorCode))
def test_project_reason_maps_to_invalid_request(code: CoordinationErrorCode) -> None:
    assert public_error_code_for_control_reason(code.value) is PublicErrorCode.INVALID_REQUEST


@pytest.mark.parametrize("code", tuple(CoordinationErrorCode))
def test_project_reason_round_trips_on_control_v2_5_wire(code: CoordinationErrorCode) -> None:
    result = _project_error(code.value)

    validate_result(result)
    parsed = parse_control_result(decode_control_frame(encode_control_frame(result)))

    assert parsed.method is ControlMethod.PROJECT
    assert isinstance(parsed.body, ControlError)
    assert parsed.body.reason == code.value
    assert parsed.body.retryable is False
