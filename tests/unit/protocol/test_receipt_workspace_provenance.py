"""The receipt result's ``workspace_provenance`` member (ADR-051, owner decision D4).

receipt-result 1.5.0 admits it on every format, in fixed words and closed tokens only; the
released 1.4.0 never does. Its ``reason`` says whether the cause can pass or lasts, and each
reason admits only its own notice. Its leaves are structural, and a paged receipt delivers it
first.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import cast

import pydantic
import pytest
from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

from finishup.application.result_delivery import page_result
from finishup.domain.workspace_provenance import (
    SESSION_OPENING_UNREADABLE,
    SESSION_OPENING_UNRECOVERABLE,
    WORKSPACE_PROVENANCE_REASONS,
    WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LASTING_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE,
    WorkspaceProvenanceReason,
    workspace_provenance_unknown_lines,
    workspace_provenance_unknown_notice,
    workspace_provenance_unknown_wire,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    ReceiptResultModel,
    ReceiptSuccessModel,
    ReceiptWorkspaceProvenanceModel,
    classify_result_leaf,
    public_model_to_wire,
)
from finishup.protocol.schemas import (
    SchemaInstanceInvalid,
    request_result_schema_version,
    validate_schema_instance,
)

_REASONS: tuple[WorkspaceProvenanceReason, ...] = (
    SESSION_OPENING_UNREADABLE,
    SESSION_OPENING_UNRECOVERABLE,
)


def _wire(
    receipt_format: str = "json", reason: WorkspaceProvenanceReason = SESSION_OPENING_UNREADABLE
) -> dict[str, JsonValue]:
    wire = _receipt_result_wire()
    if receipt_format != "json":
        wire["format"] = receipt_format
        wire["document"] = None
        wire["human_text"] = "Receipt"
    wire["workspace_provenance"] = workspace_provenance_unknown_wire(reason)
    return wire


def test_the_member_is_fixed_words_and_a_closed_reason() -> None:
    assert WORKSPACE_PROVENANCE_REASONS == (
        "session_opening_unreadable",
        "session_opening_unrecoverable",
    )
    for reason in _REASONS:
        assert workspace_provenance_unknown_wire(reason) == {
            "status": "unknown",
            "reason": reason,
            "notice": "\n".join(workspace_provenance_unknown_lines(reason)),
        }
        for line in workspace_provenance_unknown_lines(reason):
            assert "/" not in line.replace("`finishup service restart`", "")
    for other in ("ledger_down", "", None, 1):
        with pytest.raises(ValueError, match="workspace_provenance_reason_invalid"):
            workspace_provenance_unknown_lines(other)


def test_a_passing_cause_says_to_retry_and_a_lasting_one_says_it_will_not_clear() -> None:
    """Both say what happened and why it matters in the same words; only a passing cause says to
    run receipt again or restart, and only a lasting one says the record will not become readable
    again and the receipt will keep saying so."""

    passing = workspace_provenance_unknown_lines(SESSION_OPENING_UNREADABLE)
    lasting = workspace_provenance_unknown_lines(SESSION_OPENING_UNRECOVERABLE)
    assert passing == (
        WORKSPACE_PROVENANCE_UNKNOWN_LINE,
        WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
        WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE,
    )
    assert lasting == (
        WORKSPACE_PROVENANCE_UNKNOWN_LINE,
        WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
        WORKSPACE_PROVENANCE_UNKNOWN_LASTING_LINE,
    )
    assert WORKSPACE_PROVENANCE_UNKNOWN_LASTING_LINE == (
        "Why it lasts: the record is redacted or erased, its key is gone, or it is in a format "
        "this FinishUP version cannot decode, so it will not become readable again and this "
        "task's receipts will keep saying so. Running receipt again or restarting the service "
        "will not change this."
    )
    lasting_text = "\n".join(lasting)
    assert "What to do" not in lasting_text
    assert "finishup service restart" not in lasting_text
    assert "If this persists" not in lasting_text
    assert "will not become readable again" not in "\n".join(passing)
    assert workspace_provenance_unknown_notice(SESSION_OPENING_UNREADABLE) != (
        workspace_provenance_unknown_notice(SESSION_OPENING_UNRECOVERABLE)
    )


@pytest.mark.parametrize("reason", _REASONS)
@pytest.mark.parametrize("receipt_format", ["json", "text", "markdown"])
def test_every_receipt_format_admits_the_member(
    receipt_format: str, reason: WorkspaceProvenanceReason
) -> None:
    assert request_result_schema_version("receipt-result") == "1.5.0"
    receipt = ReceiptResultModel.model_validate(_wire(receipt_format, reason))
    success = receipt.root
    assert type(success) is ReceiptSuccessModel
    assert success.workspace_provenance is not None
    assert success.workspace_provenance.reason == reason
    assert success.workspace_provenance.notice == workspace_provenance_unknown_notice(reason)
    wire = public_model_to_wire(receipt)
    assert wire["workspace_provenance"] == workspace_provenance_unknown_wire(reason)
    validate_schema_instance("receipt-result", "1.5.0", cast(JsonValue, wire))


def test_a_receipt_without_the_member_omits_it() -> None:
    receipt = ReceiptResultModel.model_validate(_receipt_result_wire())
    assert "workspace_provenance" not in public_model_to_wire(receipt)


_PASSING = workspace_provenance_unknown_wire(SESSION_OPENING_UNREADABLE)
_LASTING = workspace_provenance_unknown_wire(SESSION_OPENING_UNRECOVERABLE)


@pytest.mark.parametrize(
    "member",
    [
        None,
        {**_PASSING, "notice": "The server at /srv/x is down."},
        {**_PASSING, "reason": "ledger_down"},
        {**_PASSING, "status": "client_attested"},
        {**_PASSING, "host": "example.org"},
        {"status": "unknown", "reason": "session_opening_unreadable"},
        # Each reason admits only its own notice: a lasting cause never tells the user to retry,
        # and a passing one never says the record is gone for good.
        {**_PASSING, "notice": _LASTING["notice"]},
        {**_LASTING, "notice": _PASSING["notice"]},
    ],
    ids=[
        "explicit_null",
        "free_text",
        "open_reason",
        "other_status",
        "extra",
        "no_notice",
        "passing_with_lasting_notice",
        "lasting_with_passing_notice",
    ],
)
def test_nothing_but_the_fixed_member_is_admitted(member: object) -> None:
    wire = _receipt_result_wire()
    wire["workspace_provenance"] = cast(JsonValue, member)
    with pytest.raises(pydantic.ValidationError):
        ReceiptResultModel.model_validate(wire)
    # A reader that validates by the 1.5.0 schema alone refuses the same members.
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-result", "1.5.0", wire)


@pytest.mark.parametrize(
    ("reason", "notice_of"),
    [
        (SESSION_OPENING_UNREADABLE, SESSION_OPENING_UNRECOVERABLE),
        (SESSION_OPENING_UNRECOVERABLE, SESSION_OPENING_UNREADABLE),
    ],
)
def test_the_member_model_pairs_each_reason_with_its_own_notice(
    reason: WorkspaceProvenanceReason, notice_of: WorkspaceProvenanceReason
) -> None:
    """The member's own model, not only the result schema, refuses a notice of the other reason."""

    assert ReceiptWorkspaceProvenanceModel.model_validate(
        workspace_provenance_unknown_wire(reason)
    ).model_dump() == workspace_provenance_unknown_wire(reason)
    with pytest.raises(pydantic.ValidationError, match="workspace_provenance_notice_invalid"):
        ReceiptWorkspaceProvenanceModel.model_validate(
            {
                **workspace_provenance_unknown_wire(reason),
                "notice": workspace_provenance_unknown_notice(notice_of),
            }
        )


@pytest.mark.parametrize("reason", _REASONS)
def test_the_released_1_4_0_result_never_carries_the_member(
    reason: WorkspaceProvenanceReason,
) -> None:
    wire = public_model_to_wire(ReceiptResultModel.model_validate(_wire(reason=reason)))
    validate_schema_instance("receipt-result", "1.5.0", cast(JsonValue, wire))
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-result", "1.4.0", cast(JsonValue, wire))


@pytest.mark.parametrize("reason", _REASONS)
@pytest.mark.parametrize("leaf", ["status", "reason", "notice"])
def test_every_leaf_of_the_member_is_structural(
    leaf: str, reason: WorkspaceProvenanceReason
) -> None:
    wire = public_model_to_wire(ReceiptResultModel.model_validate(_wire("text", reason)))
    assert classify_result_leaf("receipt", wire, f"/workspace_provenance/{leaf}") == (
        "public_structural"
    )


@pytest.mark.parametrize("reason", _REASONS)
def test_a_paged_receipt_delivers_the_member_whole_on_its_first_page(
    reason: WorkspaceProvenanceReason,
) -> None:
    wire = _wire("text", reason)
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
    assert {
        "path": "/workspace_provenance",
        "value": workspace_provenance_unknown_wire(reason),
    } in (items)
