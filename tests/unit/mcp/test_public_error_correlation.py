"""Every agent-facing correlation id the bridge mints must resolve in the durable ring.

Issue #191: the ids handed to an agent for deterministic failures (`INVALID_REQUEST`,
`OPERATION_PENDING`) were minted straight into the wire envelope and written to no sink, so a
maintainer handed one from a transcript found zero records. These lock the mint-and-record pairing
and the no-second-mint rule that keeps one failure on one id.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from finishup.observability.diagnostics import append_diagnostic_record, lookup_diagnostic_records
from finishup.protocol.errors import PublicErrorCode

_SERVICE_CORRELATION = "err_dddddddd-dddd-4ddd-8ddd-dddddddddddd"
_REQUEST = "req_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def diagnostic_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


def _error_of(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    return cast(dict[str, object], structured["error"])


def test_minted_invalid_request_id_resolves_to_a_record(diagnostic_root: Path) -> None:
    """The commonest agent-facing failure must not carry an id that resolves to nothing."""

    result = bridge.structured_error_result(
        PublicErrorCode.INVALID_REQUEST,
        "The request could not be validated.",
        request_id=_REQUEST,
        operation="check",
    )

    error = _error_of(result)
    correlation_id = cast(str, error["correlation_id"])
    assert correlation_id.startswith("err_")
    found = lookup_diagnostic_records(correlation_id, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["component"] == "mcp.bridge"
    assert found[0]["operation"] == "check_public_error"
    assert found[0]["reason"] == "invalid_request"
    assert found[0]["request_id"] == _REQUEST
    # The sink stays structural: no message, payload, or path ever joins the record.
    for forbidden in ("message", "payload", "path", "exception", "traceback"):
        assert forbidden not in found[0]


def test_minted_recovery_unavailable_id_resolves_to_a_record(diagnostic_root: Path) -> None:
    """The publish recovery caveat rides a rejection, and its id must still be joinable."""

    result = bridge._publish_validation_recovery_unavailable_result(_REQUEST)  # pyright: ignore[reportPrivateUsage]

    error = _error_of(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    correlation_id = cast(str, error["correlation_id"])
    found = lookup_diagnostic_records(correlation_id, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["operation"] == "publish_work_recovery_unavailable_public_error"
    assert found[0]["reason"] == "invalid_request"


def test_supplied_correlation_id_is_reused_and_not_re_recorded(diagnostic_root: Path) -> None:
    """An id another sink already owns is passed through; a second mint would split the failure."""

    append_diagnostic_record(
        correlation_id=_SERVICE_CORRELATION,
        component="service.daemon",
        operation="check_internal_error",
        reason="exception_runtime_error",
        request_id=_REQUEST,
        root=diagnostic_root,
    )

    result = bridge.structured_error_result(
        PublicErrorCode.INTERNAL_ERROR,
        "The bridge could not complete the operation.",
        request_id=_REQUEST,
        correlation_id=_SERVICE_CORRELATION,
        operation="check",
    )

    error = _error_of(result)
    assert error["correlation_id"] == _SERVICE_CORRELATION
    found = lookup_diagnostic_records(_SERVICE_CORRELATION, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["operation"] == "check_internal_error"


def test_unnamed_operation_still_records_a_bounded_token(diagnostic_root: Path) -> None:
    """A caller that names no operation must still leave a resolvable record, not a dropped one."""

    result = bridge.structured_error_result(
        PublicErrorCode.SERVICE_UNAVAILABLE,
        "The local service is unavailable; retry after it is ready.",
        retryable=True,
        request_id=_REQUEST,
        operation="Not A Token",
    )

    correlation_id = cast(str, _error_of(result)["correlation_id"])
    found = lookup_diagnostic_records(correlation_id, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["operation"] == "public_error"


@pytest.mark.anyio
async def test_dispatch_invalid_request_records_its_agent_facing_id(
    diagnostic_root: Path,
) -> None:
    """End to end through a tool entry point: validation fails before any service connection."""

    result = await bridge.dispatch_check({"protocol_version": "0.1"})

    error = _error_of(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    correlation_id = cast(str, error["correlation_id"])
    found = lookup_diagnostic_records(correlation_id, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["operation"] == "check_public_error"
    assert found[0]["reason"] == "invalid_request"
