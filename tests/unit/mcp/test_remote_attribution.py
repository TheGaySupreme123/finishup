"""The MCP status and receipt text name a claim-bound connection's producing service (ADR-051).

The structured result never changes, and a local connection's text keeps its exact bytes.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast

import pytest
from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

import finishup.mcp.server as bridge
from builders.status_wire import compact_status
from finishup.client.attribution import ServiceAttribution
from finishup.domain.receipts import (
    CLIENT_ATTESTED_WORKSPACE_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
    workspace_provenance_unknown_block,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import ReceiptResultModel, StatusResultModel, public_model_to_wire

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000083"
_ATTRIBUTION = ServiceAttribution(_SERVICE_ID, "https")
_REACHED = f"This client reached FinishUP service {_SERVICE_ID} (transport: https)."
_IDENTITY: dict[str, JsonValue] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-000000000093",
    "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
    "client": {
        "kind": "cooperative_agent",
        "version": "0.1.0",
        "integration": "cooperative_mcp",
    },
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _text(result: object) -> str:
    content = cast(list[object], getattr(result, "content"))
    return cast(str, getattr(content[0], "text"))


def _receipt() -> ReceiptResultModel:
    return ReceiptResultModel.model_validate(_receipt_result_wire())


def test_a_status_text_ends_with_the_attribution_and_its_record_is_unchanged() -> None:
    status = compact_status().result
    local = bridge.result_from_public_model(status)
    assert _text(bridge.result_from_public_model(status, attribution=None)) == _text(local)
    attributed = bridge.result_from_public_model(status, attribution=_ATTRIBUTION)
    assert _text(attributed) == "\n".join((_text(local), CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED))
    assert attributed.structuredContent == local.structuredContent
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in _text(local)


def test_a_receipt_keeps_its_exact_canonical_copy_ahead_of_the_attribution() -> None:
    receipt = _receipt()
    canonical = canonical_encode(cast(JsonValue, public_model_to_wire(receipt))).decode("utf-8")
    assert _text(bridge.result_from_public_model(receipt)) == canonical
    attributed = bridge.result_from_public_model(receipt, attribution=_ATTRIBUTION)
    assert _text(attributed) == "\n".join((canonical, CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED))
    assert (
        attributed.structuredContent == bridge.result_from_public_model(receipt).structuredContent
    )


@pytest.mark.parametrize("receipt_format", ["text", "markdown"])
def test_a_receipt_whose_provenance_is_unknown_gets_only_the_producing_service(
    receipt_format: str,
) -> None:
    wire = _receipt_result_wire()
    wire["format"] = receipt_format
    wire["document"] = None
    wire["human_text"] = "Receipt\n\n" + workspace_provenance_unknown_block(
        markdown=receipt_format == "markdown"
    )
    receipt = ReceiptResultModel.model_validate(wire)
    local = _text(bridge.result_from_public_model(receipt))
    attributed = _text(bridge.result_from_public_model(receipt, attribution=_ATTRIBUTION))
    assert attributed == "\n".join((local, _REACHED))
    assert WORKSPACE_PROVENANCE_UNKNOWN_LINE in attributed
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in attributed


# --- the bridge attributes the connection that answered -----------------------------------------


class _Client:
    def __init__(self, binding: str) -> None:
        self.workspace_binding = binding
        self.workspace_handle = "client:0123456789abcdef" if binding == "client_claim" else None
        self.service_instance_id = _SERVICE_ID
        self.transport = "https"

    async def connect(self) -> None:
        return None

    async def status(self, request: object, **_kwargs: object) -> StatusResultModel:
        del request
        return compact_status().result

    async def receipt(self, request: object, **_kwargs: object) -> ReceiptResultModel:
        del request
        return _receipt()

    async def close(self) -> None:
        return None


def _wire(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, client: _Client) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)

    async def on_demand(_kind: object, **_kwargs: object) -> object:
        return client

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], on_demand),
    )


def _status_arguments() -> dict[str, JsonValue]:
    return {
        **_IDENTITY,
        "session_id": "ses_00000000-0000-4000-8000-000000000093",
        "writer_id": "wri_00000000-0000-4000-8000-000000000093",
        "view": "compact",
        "limit": "10",
    }


def _receipt_arguments() -> dict[str, JsonValue]:
    return {
        **_IDENTITY,
        "task_id": "tsk_00000000-0000-4000-8000-000000000093",
        "session_id": "ses_00000000-0000-4000-8000-000000000093",
        "writer_id": "wri_00000000-0000-4000-8000-000000000093",
        "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
        "format": "json",
        "include": "standard",
        "redaction_profile": "default_local_export",
    }


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["status", "receipt"])
async def test_a_claim_bound_answer_names_its_producer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, operation: str
) -> None:
    _wire(monkeypatch, tmp_path, _Client("client_claim"))
    if operation == "status":
        result = await bridge.dispatch_status(_status_arguments(), bridge.build_bridge_runtime())
    else:
        result = await bridge.dispatch_receipt(_receipt_arguments(), bridge.build_bridge_runtime())
    assert result.isError is False
    assert _text(result).endswith("\n" + CLIENT_ATTESTED_WORKSPACE_LINE + "\n" + _REACHED)


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["status", "receipt"])
async def test_a_local_answer_is_not_attributed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, operation: str
) -> None:
    _wire(monkeypatch, tmp_path, _Client("local_path"))
    if operation == "status":
        result = await bridge.dispatch_status(_status_arguments(), bridge.build_bridge_runtime())
    else:
        result = await bridge.dispatch_receipt(_receipt_arguments(), bridge.build_bridge_runtime())
    assert result.isError is False
    text = _text(result)
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in text
    assert _SERVICE_ID not in text
