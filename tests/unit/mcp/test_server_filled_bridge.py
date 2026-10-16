"""Issue #1084 at the MCP bridge: sparse publish bodies and the brief status default.

The bridge forwards a publish body exactly as sparse as the agent sent it (the service fills and
records the rest), names the derived request id on every envelope it builds, and asks for the
brief status detail unless the agent named one.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

import pytest
from mcp import types
from pydantic import BaseModel

import finishup.mcp.server as bridge
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import PublishWorkRequest, StatusRequest
from finishup.protocol.publish_boilerplate import derived_publish_request_id

_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"
_ENVELOPE: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "session_id": _SESSION,
    "writer_id": _WRITER,
    "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
    "client": {"kind": "cooperative_agent", "version": "0.1.0", "integration": "cooperative_mcp"},
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _sparse_publish() -> dict[str, object]:
    return {
        **_ENVELOPE,
        "event_drafts": [
            {
                "schema": {"name": "decision_recorded", "version": "1.0.0"},
                "payload": {
                    "statement": "Keep the adapter.",
                    "rationale": "It covers the case.",
                    "authority": "harness:mcp",
                },
            }
        ],
    }


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[BaseModel]:
    seen: list[BaseModel] = []

    async def ensure(_runtime: object = bridge.BRIDGE_RUNTIME, **_kwargs: object) -> object:
        return object()

    async def invoke(
        _runtime: object,
        request: BaseModel,
        _call: Callable[[object, object], Awaitable[object]],
        _request_id: object = None,
        **_kwargs: object,
    ) -> object:
        seen.append(request)
        raise PublicOperationError(
            PublicErrorCode.EVENT_INVALID,
            "The event batch is invalid.",
            False,
            safe_details={"reason_code": "invalid_event_value_type"},
        )

    monkeypatch.setattr(bridge, "ensure_service_client", ensure)
    monkeypatch.setattr(bridge, "_invoke_with_reconnect", invoke)
    return seen


@pytest.mark.anyio
async def test_a_sparse_publish_is_forwarded_sparse_under_its_derived_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _capture(monkeypatch)
    runtime = bridge.build_bridge_runtime()
    arguments = _sparse_publish()
    derived = derived_publish_request_id(arguments)
    assert derived is not None

    result = await bridge.dispatch_publish_work(arguments, runtime)

    (forwarded,) = seen
    assert isinstance(forwarded, PublishWorkRequest)
    assert forwarded.request_id == derived
    assert forwarded.request_id_derived and forwarded.expected_frontier_latest
    # The control channel serializes exclude_unset: the service receives the sparse body and
    # derives the same id itself, so it knows the id was derived.
    sent = forwarded.model_dump(mode="json", by_alias=True, exclude_unset=True)
    assert "request_id" not in sent and "expected_frontier" not in sent
    assert PublishWorkRequest.model_validate(sent).request_id == derived
    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == derived
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_invalid_sparse_publish_names_its_derived_id_without_a_recovery_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _capture(monkeypatch)
    runtime = bridge.build_bridge_runtime()
    arguments = _sparse_publish()
    drafts = cast(list[dict[str, object]], arguments["event_drafts"])
    drafts[0]["schema"] = {"name": "decision_recorded", "version": "9.9.9"}

    result = await bridge.dispatch_publish_work(arguments, runtime)

    # An invalid sparse body can never have committed under its derived id: no recovery read.
    assert seen == []
    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == derived_publish_request_id(arguments)
    error = cast(dict[str, object], result.structuredContent["error"])
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
@pytest.mark.parametrize(("sent", "expected"), [(None, "brief"), ("full", "full")])
async def test_status_asks_for_the_brief_detail_unless_the_agent_names_one(
    monkeypatch: pytest.MonkeyPatch, sent: str | None, expected: str
) -> None:
    seen = _capture(monkeypatch)
    runtime = bridge.build_bridge_runtime()
    arguments: dict[str, object] = {
        **_ENVELOPE,
        "request_id": "req_00000000-0000-4000-8000-000000001084",
        "view": "compact",
    }
    if sent is not None:
        arguments["detail"] = sent

    result: types.CallToolResult = await bridge.dispatch_status(arguments, runtime)

    (forwarded,) = seen
    assert isinstance(forwarded, StatusRequest)
    assert forwarded.detail == expected
    assert forwarded.limit == "20"
    assert result.isError is True
    await bridge.close_bridge_runtime(runtime)
