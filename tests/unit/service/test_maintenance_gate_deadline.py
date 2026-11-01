"""An ordinary control call must not wait behind a human ceremony forever.

The installation-recovery ceremonies take the installation-wide maintenance lease and hold it
across an unbounded human wait -- someone reading a confirmation screen, or walking away from it.
`_dispatch_ready` takes that same lock, so an unbounded acquire turns one open prompt into a
service that answers nothing and reports no reason. The caller's own deadline has to bound it.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from finishup.ports.control import ControlCallRequest, ControlError, ControlMethod
from finishup.protocol.models import CheckRequest
from finishup.service.daemon import ServiceDaemon

_INSTANCE_ID = "svc_00000000-0000-4000-8000-0000000000b1"
_RPC_ID = "rpc_00000000-0000-4000-8000-0000000000b2"
_REQUEST_ID = "req_00000000-0000-4000-8000-0000000000b3"


def _request(deadline_ms: int | None) -> ControlCallRequest:
    body = CheckRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _REQUEST_ID,
            "session_id": "ses_00000000-0000-4000-8000-0000000000b4",
            "writer_id": "wri_00000000-0000-4000-8000-0000000000b5",
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
        deadline_ms=deadline_ms,
    )


def _daemon(gate: asyncio.Lock) -> Any:
    # A bare instance keeps the test on gate behaviour: nothing past the gate is reached.
    daemon = ServiceDaemon.__new__(ServiceDaemon)
    setattr(daemon, "_composition", SimpleNamespace(maintenance_gate=gate))
    return daemon


@pytest.mark.anyio
async def test_held_maintenance_gate_reports_request_timeout_instead_of_hanging() -> None:
    gate = asyncio.Lock()
    await gate.acquire()
    daemon = _daemon(gate)

    with pytest.raises(ControlError) as caught:
        await asyncio.wait_for(
            daemon._dispatch_ready(SimpleNamespace(), _request(50), None),
            timeout=5.0,
        )

    assert caught.value.reason == "request_timeout"
    # A ceremony ends; the caller is told to come back rather than that the call is impossible.
    assert caught.value.retryable is True
    assert gate.locked()


@pytest.mark.anyio
async def test_the_gate_is_released_for_the_next_caller() -> None:
    """A bounded acquire must not leak the lease when the guarded call itself fails."""

    gate = asyncio.Lock()
    daemon = _daemon(gate)
    marker = ControlError("vault_locked")

    async def _under_gate(*_args: object, **_kwargs: object) -> object:
        assert gate.locked()
        raise marker

    setattr(daemon, "_dispatch_ready_under_maintenance_gate", _under_gate)

    for _ in range(2):
        with pytest.raises(ControlError) as caught:
            await daemon._dispatch_ready(SimpleNamespace(), _request(None), None)
        assert caught.value is marker
        assert not gate.locked()
