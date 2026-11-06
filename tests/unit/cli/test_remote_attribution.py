"""The CLI's human status and receipt name a claim-bound connection's producing service (ADR-051).

A local connection's output keeps its exact bytes; JSON output is never attributed.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import json
import sys
from typing import cast

import pytest
from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

from builders.status_wire import compact_status
from finishup.cli import app as app_module
from finishup.cli.render import render_human_receipt, render_human_status
from finishup.client.attribution import ServiceAttribution
from finishup.domain.receipts import (
    CLIENT_ATTESTED_WORKSPACE_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
    client_attested_receipt_block,
    workspace_provenance_unknown_block,
)
from finishup.protocol.models import (
    ReceiptSuccessModel,
    StatusRequest,
    StatusResultModel,
    StatusSuccessModel,
    public_model_to_wire,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000082"
_ATTRIBUTION = ServiceAttribution(_SERVICE_ID, "ssh")
_REACHED = f"This client reached FinishUP service {_SERVICE_ID} (transport: ssh)."


def _status() -> StatusSuccessModel:
    success = compact_status().result.root
    assert type(success) is StatusSuccessModel
    return success


def _json_receipt() -> ReceiptSuccessModel:
    return ReceiptSuccessModel.model_validate(_receipt_result_wire())


def _text_receipt(block: str | None = None) -> ReceiptSuccessModel:
    wire = _receipt_result_wire()
    wire["format"] = "text"
    wire["document"] = None
    if block is None:
        block = client_attested_receipt_block(_SERVICE_ID, markdown=False)
    wire["human_text"] = "Receipt\n\n" + block
    return ReceiptSuccessModel.model_validate(wire)


def test_status_ends_with_the_attribution_and_is_unchanged_without_one() -> None:
    status = _status()
    local = render_human_status(status)
    assert render_human_status(status, attribution=None) == local
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in local
    assert render_human_status(status, attribution=_ATTRIBUTION) == "\n".join(
        (local, CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)
    )


def test_a_json_receipt_ends_with_the_attribution() -> None:
    receipt = _json_receipt()
    local = render_human_receipt(receipt)
    assert render_human_receipt(receipt, attribution=None) == local
    assert render_human_receipt(receipt, attribution=_ATTRIBUTION) == "\n".join(
        (local, CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)
    )


def test_a_text_receipt_carrying_the_service_block_gets_only_the_transport() -> None:
    receipt = _text_receipt()
    rendered = render_human_receipt(receipt, attribution=_ATTRIBUTION)
    assert rendered == render_human_receipt(receipt) + "\n" + _REACHED
    assert rendered.count(CLIENT_ATTESTED_WORKSPACE_LINE) == 1


def test_a_text_receipt_whose_provenance_is_unknown_gets_only_the_transport() -> None:
    receipt = _text_receipt(workspace_provenance_unknown_block(markdown=False))
    rendered = render_human_receipt(receipt, attribution=_ATTRIBUTION)
    assert rendered == render_human_receipt(receipt) + "\n" + _REACHED
    assert WORKSPACE_PROVENANCE_UNKNOWN_LINE in rendered
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in rendered


# --- the command wires the connection's attribution ---------------------------------------------

_STATUS_REQUEST = json.dumps(
    {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000092",
        "actor": {"actor_id": "harness:cli", "actor_type": "harness"},
        "client": {"kind": "yoetz_cli", "version": "0.1.0", "integration": "local_cli"},
        "session_id": "ses_00000000-0000-4000-8000-000000000092",
        "writer_id": "wri_00000000-0000-4000-8000-000000000092",
        "view": "compact",
        "limit": "10",
    }
)


class _Client:
    def __init__(self, binding: str, result: StatusResultModel) -> None:
        self.workspace_binding = binding
        self.workspace_handle = "client:0123456789abcdef" if binding == "client_claim" else None
        self.service_instance_id = _SERVICE_ID
        self.transport = "ssh"
        self.result = result
        self.closed = False

    async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
        del request, deadline_ms
        return self.result

    async def close(self) -> None:
        self.closed = True


def _run_status(
    monkeypatch: pytest.MonkeyPatch, binding: str, *, json_output: bool, tty: bool
) -> tuple[int, StatusResultModel]:
    result = compact_status().result
    client = _Client(binding, result)

    async def build(*_args: object, **_kwargs: object) -> object:
        return client

    monkeypatch.setattr(app_module, "build_service_client", build)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
    code = asyncio.run(
        app_module._call_workflow(  # pyright: ignore[reportPrivateUsage]
            "status", StatusRequest, None, _STATUS_REQUEST, json_output, None
        )
    )
    assert client.closed
    return code, result


def test_the_status_command_names_a_claim_bound_producer(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, result = _run_status(monkeypatch, "client_claim", json_output=False, tty=True)
    assert code == 0
    success = cast(StatusSuccessModel, result.root)
    assert capsys.readouterr().out == (
        render_human_status(success, attribution=_ATTRIBUTION) + "\n"
    )


def test_the_status_command_output_of_a_local_connection_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, result = _run_status(monkeypatch, "local_path", json_output=False, tty=True)
    assert code == 0
    success = cast(StatusSuccessModel, result.root)
    assert capsys.readouterr().out == render_human_status(success) + "\n"


def test_json_status_is_never_attributed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, result = _run_status(monkeypatch, "client_claim", json_output=True, tty=True)
    assert code == 0
    out = capsys.readouterr().out
    assert json.loads(out) == json.loads(json.dumps(public_model_to_wire(result)))
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in out
    assert _SERVICE_ID not in out
