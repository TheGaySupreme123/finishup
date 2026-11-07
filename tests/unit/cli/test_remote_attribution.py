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
from finishup.domain.workspace_provenance import (
    SESSION_OPENING_UNREADABLE,
    WORKSPACE_PROVENANCE_REASONS,
    WorkspaceProvenanceReason,
    workspace_provenance_unknown_lines,
    workspace_provenance_unknown_wire,
)
from finishup.protocol.models import (
    ReceiptRequest,
    ReceiptResultModel,
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


_REASONS: tuple[WorkspaceProvenanceReason, ...] = WORKSPACE_PROVENANCE_REASONS


def _own_and_others(reason: WorkspaceProvenanceReason) -> tuple[str, tuple[str, ...]]:
    """The line only ``reason``'s section ends with, and the lines every other reason's ends with
    (the passing cause's retry line, and each lasting cause's own "Why it lasts" line)."""

    own = workspace_provenance_unknown_lines(reason)[-1]
    others = tuple(
        workspace_provenance_unknown_lines(other)[-1]
        for other in WORKSPACE_PROVENANCE_REASONS
        if other != reason
    )
    return own, others


@pytest.mark.parametrize("reason", _REASONS)
def test_a_text_receipt_whose_provenance_is_unknown_gets_only_the_transport(
    reason: WorkspaceProvenanceReason,
) -> None:
    receipt = _text_receipt(workspace_provenance_unknown_block(markdown=False, reason=reason))
    rendered = render_human_receipt(receipt, attribution=_ATTRIBUTION)
    assert rendered == render_human_receipt(receipt) + "\n" + _REACHED
    assert WORKSPACE_PROVENANCE_UNKNOWN_LINE in rendered
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in rendered


# --- decision D4: every format says when the provenance is unknown ------------------------------


def _unknown(
    receipt: ReceiptSuccessModel, reason: WorkspaceProvenanceReason = SESSION_OPENING_UNREADABLE
) -> ReceiptSuccessModel:
    wire = receipt.model_dump(mode="json", by_alias=True, exclude_unset=True)
    wire["workspace_provenance"] = workspace_provenance_unknown_wire(reason)
    return ReceiptSuccessModel.model_validate(wire)


@pytest.mark.parametrize("reason", _REASONS)
def test_a_json_receipt_of_unknown_provenance_shows_the_section_and_only_the_transport(
    reason: WorkspaceProvenanceReason,
) -> None:
    """A JSON receipt has no text section, so the CLI shows the fixed one for the result's own
    reason: a passing cause says to retry, a lasting one says it will not clear and never says
    to retry or restart."""

    receipt = _unknown(_json_receipt(), reason)
    local = render_human_receipt(receipt)
    block = workspace_provenance_unknown_block(markdown=False, reason=reason)
    assert local == render_human_receipt(_json_receipt()) + "\n" + block
    rendered = render_human_receipt(receipt, attribution=_ATTRIBUTION)
    assert rendered == local + "\n" + _REACHED
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in rendered
    for line in workspace_provenance_unknown_lines(reason):
        assert rendered.count(line) == 1
    own, others = _own_and_others(reason)
    assert own in rendered
    assert not any(line in rendered for line in others)


@pytest.mark.parametrize("reason", _REASONS)
def test_a_text_receipt_of_unknown_provenance_shows_its_section_once(
    reason: WorkspaceProvenanceReason,
) -> None:
    receipt = _unknown(
        _text_receipt(workspace_provenance_unknown_block(markdown=False, reason=reason)), reason
    )
    rendered = render_human_receipt(receipt, attribution=_ATTRIBUTION)
    assert rendered == render_human_receipt(receipt) + "\n" + _REACHED
    assert rendered.count(WORKSPACE_PROVENANCE_UNKNOWN_LINE) == 1
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in rendered
    own, others = _own_and_others(reason)
    assert rendered.count(own) == 1
    assert not any(line in rendered for line in others)


@pytest.mark.parametrize("reason", _REASONS)
def test_a_withheld_text_receipt_of_unknown_provenance_still_shows_the_section(
    reason: WorkspaceProvenanceReason,
) -> None:
    wire = _text_receipt().model_dump(mode="json", by_alias=True, exclude_unset=True)
    wire["human_text"] = {
        "omitted": True,
        "category": "finding_summary",
        "reason": "local_disclosure_not_authorized",
    }
    wire["workspace_provenance"] = workspace_provenance_unknown_wire(reason)
    receipt = ReceiptSuccessModel.model_validate(wire)
    rendered = render_human_receipt(receipt, attribution=_ATTRIBUTION)
    assert workspace_provenance_unknown_block(markdown=False, reason=reason) in rendered
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in rendered
    assert not any(line in rendered for line in _own_and_others(reason)[1])
    assert rendered.endswith("\n" + _REACHED)


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


_RECEIPT_REQUEST = json.dumps(
    {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000094",
        "actor": {"actor_id": "harness:cli", "actor_type": "harness"},
        "client": {"kind": "yoetz_cli", "version": "0.1.0", "integration": "local_cli"},
        "task_id": "tsk_00000000-0000-4000-8000-000000000094",
        "session_id": "ses_00000000-0000-4000-8000-000000000094",
        "writer_id": "wri_00000000-0000-4000-8000-000000000094",
        "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
        "format": "json",
        "include": "standard",
        "redaction_profile": "default_local_export",
    }
)


class _ReceiptClient(_Client):
    def __init__(self, binding: str, result: ReceiptResultModel) -> None:
        super().__init__(binding, compact_status().result)
        self.receipt_result = result

    async def receipt(self, request: object, *, deadline_ms: int | None = None) -> object:
        del request, deadline_ms
        return self.receipt_result


@pytest.mark.parametrize("reason", _REASONS)
@pytest.mark.parametrize("json_output", [False, True])
def test_the_receipt_command_says_an_unknown_provenance_in_every_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    json_output: bool,
    reason: WorkspaceProvenanceReason,
) -> None:
    """Decision D4: a claim-bound JSON receipt of unknown provenance shows the fixed section for
    its reason and no "read on the client" line on a terminal; JSON output carries the member
    itself, reason included."""

    wire = _receipt_result_wire()
    wire["workspace_provenance"] = workspace_provenance_unknown_wire(reason)
    result = ReceiptResultModel.model_validate(wire)
    client = _ReceiptClient("client_claim", result)

    async def build(*_args: object, **_kwargs: object) -> object:
        return client

    monkeypatch.setattr(app_module, "build_service_client", build)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    code = asyncio.run(
        app_module._call_workflow(  # pyright: ignore[reportPrivateUsage]
            "receipt", ReceiptRequest, None, _RECEIPT_REQUEST, json_output, None
        )
    )
    assert code == 0
    assert client.closed
    out = capsys.readouterr().out
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in out
    if json_output:
        assert json.loads(out)["workspace_provenance"] == workspace_provenance_unknown_wire(reason)
        return
    success = cast(ReceiptSuccessModel, result.root)
    assert out == render_human_receipt(success, attribution=_ATTRIBUTION) + "\n"
    assert workspace_provenance_unknown_block(markdown=False, reason=reason) in out
    assert not any(line in out for line in _own_and_others(reason)[1])
    assert out.endswith(_REACHED + "\n")
