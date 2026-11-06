"""The receipt result's ``workspace_provenance`` member (ADR-051, owner decision D4).

receipt-result 1.5.0 admits it on every format, in fixed words and closed tokens only; the
released 1.4.0 never does. Its leaves are structural, and a paged receipt delivers it first.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import cast

import pydantic
import pytest
from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

from finishup.application.result_delivery import page_result
from finishup.domain.workspace_provenance import (
    WORKSPACE_PROVENANCE_REASONS,
    WORKSPACE_PROVENANCE_UNKNOWN_LINES,
    WORKSPACE_PROVENANCE_UNKNOWN_NOTICE,
    workspace_provenance_unknown_wire,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    ReceiptResultModel,
    ReceiptSuccessModel,
    classify_result_leaf,
    public_model_to_wire,
)
from finishup.protocol.schemas import (
    SchemaInstanceInvalid,
    request_result_schema_version,
    validate_schema_instance,
)


def _wire(receipt_format: str = "json") -> dict[str, JsonValue]:
    wire = _receipt_result_wire()
    if receipt_format != "json":
        wire["format"] = receipt_format
        wire["document"] = None
        wire["human_text"] = "Receipt"
    wire["workspace_provenance"] = workspace_provenance_unknown_wire()
    return wire


def test_the_member_is_fixed_words_and_a_closed_reason() -> None:
    assert workspace_provenance_unknown_wire() == {
        "status": "unknown",
        "reason": "session_opening_unreadable",
        "notice": "\n".join(WORKSPACE_PROVENANCE_UNKNOWN_LINES),
    }
    assert WORKSPACE_PROVENANCE_REASONS == ("session_opening_unreadable",)
    for line in WORKSPACE_PROVENANCE_UNKNOWN_LINES:
        assert "/" not in line.replace("`finishup service restart`", "")


@pytest.mark.parametrize("receipt_format", ["json", "text", "markdown"])
def test_every_receipt_format_admits_the_member(receipt_format: str) -> None:
    assert request_result_schema_version("receipt-result") == "1.5.0"
    receipt = ReceiptResultModel.model_validate(_wire(receipt_format))
    success = receipt.root
    assert type(success) is ReceiptSuccessModel
    assert success.workspace_provenance is not None
    assert success.workspace_provenance.notice == WORKSPACE_PROVENANCE_UNKNOWN_NOTICE
    assert public_model_to_wire(receipt)["workspace_provenance"] == (
        workspace_provenance_unknown_wire()
    )


def test_a_receipt_without_the_member_omits_it() -> None:
    receipt = ReceiptResultModel.model_validate(_receipt_result_wire())
    assert "workspace_provenance" not in public_model_to_wire(receipt)


@pytest.mark.parametrize(
    "member",
    [
        None,
        {**workspace_provenance_unknown_wire(), "notice": "The server at /srv/x is down."},
        {**workspace_provenance_unknown_wire(), "reason": "ledger_down"},
        {**workspace_provenance_unknown_wire(), "status": "client_attested"},
        {**workspace_provenance_unknown_wire(), "host": "example.org"},
        {"status": "unknown", "reason": "session_opening_unreadable"},
    ],
    ids=["explicit_null", "free_text", "open_reason", "other_status", "extra", "no_notice"],
)
def test_nothing_but_the_fixed_member_is_admitted(member: object) -> None:
    wire = _receipt_result_wire()
    wire["workspace_provenance"] = cast(JsonValue, member)
    with pytest.raises(pydantic.ValidationError):
        ReceiptResultModel.model_validate(wire)


def test_the_released_1_4_0_result_never_carries_the_member() -> None:
    wire = public_model_to_wire(ReceiptResultModel.model_validate(_wire()))
    validate_schema_instance("receipt-result", "1.5.0", cast(JsonValue, wire))
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-result", "1.4.0", cast(JsonValue, wire))


@pytest.mark.parametrize("leaf", ["status", "reason", "notice"])
def test_every_leaf_of_the_member_is_structural(leaf: str) -> None:
    wire = public_model_to_wire(ReceiptResultModel.model_validate(_wire("text")))
    assert classify_result_leaf("receipt", wire, f"/workspace_provenance/{leaf}") == (
        "public_structural"
    )


def test_a_paged_receipt_delivers_the_member_whole_on_its_first_page() -> None:
    wire = _wire("text")
    wire["human_text"] = "\n".join(
        f"Section line {i}: " + "plain receipt prose. " * 6 for i in range(150)
    )
    page = page_result(
        wire,
        method="receipt",
        selector={"request_id": wire["request_id"]},
        writer_id="wri_00000000-0000-4000-8000-000000000095",
        sink="agent_context",
        position=0,
    )
    assert page["next_cursor"] is not None
    items = cast(list[dict[str, JsonValue]], page["items"])
    paths = [item["path"] for item in items]
    assert paths.index("/workspace_provenance") < paths.index("/human_text")
    assert {"path": "/workspace_provenance", "value": workspace_provenance_unknown_wire()} in items
