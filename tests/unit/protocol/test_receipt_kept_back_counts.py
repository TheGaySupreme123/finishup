"""How many files listed mode kept back, on the receipt (ADR-051 decision 5, open question 2).

Maintainer decision 2026-11-07 ("add the count now"). A claim-bound check records how many task
inputs and declared tests its client's listed mode kept from review on check-recorded 1.7.0 (the
released 1.6.0 never carries it), and the receipt's live ``outside_reads_not_listed`` gap carries
the same bounded counts on receipt-document 1.4.0 (the released 1.3.0 never does). Every format
says the number in one fixed line, then the owner's two ways out: the gap's detail (JSON), the
markdown and text receipts, the CLI's JSON receipt, and the compact MCP receipt summary (only the
fallback when the canonical copy cannot be encoded). Counts only, never which file. The MCP
receipt itself, paged or not, is in ``tests/unit/mcp/test_receipt_kept_back_delivery.py``; the
terminal interface's in ``tests/unit/tui/test_receipt_kept_back.py``.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, cast

import pytest
from tests.unit.kernel import test_receipt_builder as receipt_test
from tests.unit.protocol.test_reviewer_check_schema_versions import _decode, _event_body

from finishup.domain.events import encode_payload
from finishup.domain.findings import CheckVerdict
from finishup.domain.receipts import (
    MAX_KEPT_BACK_COUNT,
    OUTSIDE_READS_NOT_LISTED_GAP,
    OUTSIDE_READS_NOT_LISTED_SHORT_SENTENCE,
    OutsideReadsKeptBack,
    ReceiptGap,
    ReceiptVersionSlice,
    SchemaVersionEntry,
    check_time_change_gap_sentence,
    kept_back_from_wire,
    outside_reads_kept_back_sentence,
    receipt_document_from_json,
    receipt_document_to_json,
    render_receipt_human,
)
from finishup.kernel.deterministic_checks import CaseGap
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_KEPT = OutsideReadsKeptBack(task_inputs=3, declared_tests=1)
_COUNT_LINE = (
    "3 task inputs and 1 declared test outside the folders this server may read were kept back."
)


def test_the_counts_are_bounded_and_say_the_number_in_fixed_words() -> None:
    assert outside_reads_kept_back_sentence(_KEPT) == _COUNT_LINE
    assert outside_reads_kept_back_sentence(OutsideReadsKeptBack(1, 0)) == (
        "1 task input and 0 declared tests outside the folders this server may read was kept back."
    )
    assert OutsideReadsKeptBack.from_wire(_KEPT.as_wire()) == _KEPT
    assert _KEPT.as_wire() == {"declared_tests": 1, "task_inputs": 3}
    # Nothing kept back is no counts at all; a larger count is clamped to the bound.
    assert OutsideReadsKeptBack.clamped(0, 0) is None
    assert OutsideReadsKeptBack.clamped(10_000, 2) == OutsideReadsKeptBack(MAX_KEPT_BACK_COUNT, 2)
    for wrong in ((0, 0), (-1, 1), (MAX_KEPT_BACK_COUNT + 1, 0), (True, 1)):
        with pytest.raises(ProtocolValueError):
            OutsideReadsKeptBack(*cast(tuple[int, int], wrong))
    wrong_wires: tuple[object, ...] = (
        {"task_inputs": 1},
        {"declared_tests": 0, "task_inputs": 1, "path": "/x"},
        [],
    )
    for wire in wrong_wires:
        with pytest.raises(ProtocolValueError):
            OutsideReadsKeptBack.from_wire(wire)


def test_check_recorded_carries_the_counts_only_on_1_7() -> None:
    body: dict[str, Any] = {**_event_body(), "outside_reads_kept_back": _KEPT.as_wire()}
    for version in ("1.4.0", "1.5.0", "1.6.0"):
        # The released readers refuse the field, by decoder and by schema.
        with pytest.raises(ProtocolValueError) as refused:
            _decode(version, body)
        assert str(refused.value) == "unknown_payload_field"
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-recorded", version, body)
    decoded = _decode("1.7.0", body)
    validate_schema_instance("check-recorded", "1.7.0", body)
    assert getattr(decoded, "outside_reads_kept_back") == _KEPT
    assert canonical_encode(encode_payload(decoded)) == canonical_encode(body)
    # 1.7.0 exists exactly for the counts, and the schema refuses two zeros.
    with pytest.raises(ProtocolValueError):
        _decode("1.7.0", _event_body())
    zero = {**body, "outside_reads_kept_back": {"declared_tests": 0, "task_inputs": 0}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("check-recorded", "1.7.0", zero)


def _versions(artifact: str) -> ReceiptVersionSlice:
    return replace(
        receipt_test._versions(),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", artifact),),
    )


def _receipt(artifact: str = "1.4.0", *, counts: OutsideReadsKeptBack | None = _KEPT) -> Any:  # noqa: ANN401
    coverage = receipt_test._coverage(gaps=(OUTSIDE_READS_NOT_LISTED_GAP,))
    check = replace(
        receipt_test._check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        outside_reads_kept_back=counts,
    )
    context = receipt_test._context(
        coverage=coverage,
        gaps=(CaseGap(OUTSIDE_READS_NOT_LISTED_GAP, OUTSIDE_READS_NOT_LISTED_GAP, ()),),
        check=check,
    )
    return receipt_test.build_receipt(
        context,
        receipt_test.receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        receipt_test.task_id("tsk_00000000-0000-4000-8000-000000000001"),
        receipt_test.session_id("ses_00000000-0000-4000-8000-000000000001"),
        receipt_test.timestamp_from_string("2026-07-19T00:00:00.000Z"),
        _versions(artifact),
        receipt_test.ReceiptRedactionProfile.FULL_LOCAL,
        receipt_test.ReceiptInclude.FULL,
    )


def kept_back_receipt_result(output_format: str) -> dict[str, Any]:
    """A valid receipt result whose live ``outside_reads_not_listed`` gap carries ``_KEPT``: the
    receipt-document 1.4.0 itself for ``json``, else its rendered ``human_text`` and no document,
    as the service returns each format. Shared by the MCP and terminal-interface tests."""

    from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

    from finishup.protocol.models import ReceiptResultModel

    receipt = _receipt()
    document = cast(dict[str, Any], json.loads(json.dumps(receipt_document_to_json(receipt))))
    wire = cast(dict[str, Any], _receipt_result_wire())
    for key in (
        "receipt_id",
        "task_id",
        "session_id",
        "subject_frontier",
        "conclusion",
        "coverage",
        "suppressed_finding_count",
        "versions",
    ):
        wire[key] = document[key]
    if output_format == "json":
        wire["document"] = document
    else:
        wire["format"] = output_format
        wire["document"] = None
        wire["human_text"] = render_receipt_human(receipt, markdown=output_format == "markdown")
    ReceiptResultModel.model_validate(wire)
    return wire


def test_the_receipt_says_how_many_in_every_format() -> None:
    receipt = _receipt()
    (gap,) = (gap for gap in receipt.gaps if gap.code == OUTSIDE_READS_NOT_LISTED_GAP)
    assert gap.kept_back == _KEPT
    sentence = check_time_change_gap_sentence(OUTSIDE_READS_NOT_LISTED_GAP)
    assert sentence is not None
    # The count line first, then the owner's two ways out, unchanged.
    assert gap.detail == f"{_COUNT_LINE} {sentence}"
    wire = receipt_document_to_json(receipt)
    validate_schema_instance("receipt-document", "1.4.0", json.loads(json.dumps(wire)))
    assert receipt_document_to_json(receipt_document_from_json(wire)) == wire
    assert kept_back_from_wire(wire) == _KEPT
    for rendered in (
        render_receipt_human(receipt, markdown=True),
        render_receipt_human(receipt, markdown=False),
    ):
        assert _COUNT_LINE in rendered
        assert "`finishup server folders add NAME FOLDER`" in rendered
    # Never which file: the counts are integers beside a closed code.
    assert set(cast(dict[str, Any], next(iter(cast(list[Any], wire["gaps"]))))) >= {"kept_back"}


def test_the_released_receipt_document_never_carries_the_counts() -> None:
    wire = receipt_document_to_json(_receipt())
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-document", "1.3.0", json.loads(json.dumps(wire)))
    # A 1.3.0 artifact keeps the count line in its detail but carries no structured counts.
    released = _receipt("1.3.0")
    (gap,) = (gap for gap in released.gaps if gap.code == OUTSIDE_READS_NOT_LISTED_GAP)
    assert gap.kept_back is None and gap.detail is not None and _COUNT_LINE in gap.detail
    validate_schema_instance(
        "receipt-document",
        "1.3.0",
        json.loads(json.dumps(receipt_document_to_json(released))),
    )
    # The counts stand only beside their own live code.
    with pytest.raises(ProtocolValueError):
        ReceiptGap("task_input_outside_not_admitted", (), kept_back=_KEPT)


def test_a_check_without_counts_keeps_the_count_free_sentence() -> None:
    receipt = _receipt(counts=None)
    (gap,) = (gap for gap in receipt.gaps if gap.code == OUTSIDE_READS_NOT_LISTED_GAP)
    assert gap.kept_back is None
    assert gap.detail == check_time_change_gap_sentence(OUTSIDE_READS_NOT_LISTED_GAP)


def test_the_cli_json_receipt_and_the_mcp_summary_say_the_number() -> None:
    from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

    from finishup.cli.render import render_human_receipt
    from finishup.mcp.summaries import summary_for_receipt
    from finishup.protocol.models import ReceiptSuccessModel

    result = _receipt_result_wire()
    document = cast(dict[str, Any], result["document"])
    gaps = cast(list[Any], document.get("gaps") or [])
    gaps.append(
        {"code": OUTSIDE_READS_NOT_LISTED_GAP, "subject_refs": [], "kept_back": _KEPT.as_wire()}
    )
    document["gaps"] = gaps
    fields: dict[str, Any] = {**result, "coverage": receipt_test._coverage(), "human_text": None}
    model = ReceiptSuccessModel.model_construct(**fields)
    rendered = render_human_receipt(model)
    assert f"{_COUNT_LINE} {OUTSIDE_READS_NOT_LISTED_SHORT_SENTENCE}" in rendered
    summary = summary_for_receipt(result)
    assert _COUNT_LINE in summary
    # Malformed counts read as none: a surface never shows a number it cannot trust.
    gaps[-1] = {"code": OUTSIDE_READS_NOT_LISTED_GAP, "kept_back": {"task_inputs": "3"}}
    assert kept_back_from_wire(document) is None
    assert "kept back" not in render_human_receipt(model)
