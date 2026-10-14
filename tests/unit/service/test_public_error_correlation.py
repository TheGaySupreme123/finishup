"""A workflow public failure framed as ok:false must carry a recorded correlation id.

Issue #191: `_public_operation_failure_result` bound a freshly minted id onto an error that never
raised past a boundary recorder, so nothing was ever written under it and the agent-facing id
resolved to nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from finishup.observability.diagnostics import append_diagnostic_record, lookup_diagnostic_records
from finishup.ports.control import ControlCallRequest, ControlMethod
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import CheckRequest, public_model_to_wire
from finishup.service.daemon import ServiceDaemon

_INSTANCE_ID = "svc_00000000-0000-4000-8000-0000000000a1"
_RPC_ID = "rpc_00000000-0000-4000-8000-0000000000a2"
_REQUEST_ID = "req_00000000-0000-4000-8000-0000000000a3"


@pytest.fixture(autouse=True)
def diagnostic_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


def _check_request() -> ControlCallRequest:
    body = CheckRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _REQUEST_ID,
            "session_id": "ses_00000000-0000-4000-8000-0000000000a4",
            "writer_id": "wri_00000000-0000-4000-8000-0000000000a5",
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "mode": "deterministic_only",
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
    )
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=_RPC_ID,
        service_instance_id=_INSTANCE_ID,
        service_generation="7",
        method=ControlMethod.CHECK,
        body=body,
    )


def _frame(error: PublicOperationError) -> dict[str, object]:
    # The method reads only the request; a bare instance keeps the test on the framing behavior.
    daemon = ServiceDaemon.__new__(ServiceDaemon)
    result = daemon._public_operation_failure_result(  # pyright: ignore[reportPrivateUsage]
        _check_request(), error
    )
    assert result.outcome == "ok"
    return cast(dict[str, object], public_model_to_wire(result.body))


def test_unbound_workflow_failure_mints_and_records_one_id(diagnostic_root: Path) -> None:
    """The id that reaches the caller is the id the durable ring holds."""

    wire = _frame(
        PublicOperationError(
            PublicErrorCode.OPERATION_PENDING,
            "operation_pending",
            True,
        )
    )

    error = cast(dict[str, object], wire["error"])
    correlation_id = cast(str, error["correlation_id"])
    assert correlation_id.startswith("err_")
    found = lookup_diagnostic_records(correlation_id, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["component"] == "service.daemon"
    assert found[0]["operation"] == "check_public_error"
    assert found[0]["reason"] == "operation_pending"
    assert found[0]["request_id"] == _REQUEST_ID


def test_unbound_event_invalid_records_protocol_reason_code(diagnostic_root: Path) -> None:
    """Issue #579: diagnostics --correlation-id must name unsorted_set_field, not only event_invalid."""

    wire = _frame(
        PublicOperationError(
            PublicErrorCode.EVENT_INVALID,
            "The event batch is invalid. Correct the event payload before retrying.",
            False,
            safe_details={
                "reason_code": "unsorted_set_field",
                "field": "/event_drafts/4/payload/obligation_refs",
            },
        )
    )

    error = cast(dict[str, object], wire["error"])
    correlation_id = cast(str, error["correlation_id"])
    found = lookup_diagnostic_records(correlation_id, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["operation"] == "check_public_error"
    assert found[0]["reason"] == "event_invalid"
    assert found[0]["reason_code"] == "unsorted_set_field"


def test_already_bound_workflow_failure_is_not_re_recorded(diagnostic_root: Path) -> None:
    """An error that already carries a recorded id keeps it; a second mint would split it."""

    bound = "err_ffffffff-ffff-4fff-8fff-ffffffffffff"
    # The sink that minted the id wrote its record; the daemon boundary must add nothing.
    append_diagnostic_record(
        correlation_id=bound,
        component="workflow",
        operation="check_public_error",
        reason="frontier_conflict",
        request_id=_REQUEST_ID,
        root=diagnostic_root,
    )
    wire = _frame(
        PublicOperationError(
            PublicErrorCode.FRONTIER_CONFLICT,
            "frontier_conflict",
            False,
            correlation_id=bound,
        )
    )

    error = cast(dict[str, object], wire["error"])
    assert error["correlation_id"] == bound
    found = lookup_diagnostic_records(bound, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["component"] == "workflow"
