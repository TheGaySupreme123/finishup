"""How many files listed mode kept back reaches an agent through MCP (ADR-051 decision 5).

Maintainer decision 2026-11-07 ("add the count now"). An MCP receipt, paged or not, reaches the
agent as the receipt itself: unpaged, its canonical JSON on the text channel beside the same
``structuredContent``; paged, each delivery page's canonical JSON with the handle first. The
compact receipt summary is only the fallback when that encoding fails. So the number reaches an
agent inside the receipt: for a JSON receipt the live ``outside_reads_not_listed`` gap's
``detail`` (the count line, then the owner's two ways out) and its ``kept_back``; for a text or
markdown receipt its ``human_text``. These tests send such a receipt through the bridge's own
projection (``result_from_public_model``) for every host, whole and cut into pages that are then
reassembled. Counts only, never which file.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from tests.unit.protocol.test_receipt_kept_back_counts import (
    _COUNT_LINE,
    _KEPT,
    kept_back_receipt_result,
)

import finishup.application.result_delivery as delivery_module
import finishup.mcp.server as bridge
from finishup.application.result_delivery import decode_handle, page_result
from finishup.domain.receipts import OUTSIDE_READS_NOT_LISTED_GAP, kept_back_from_wire
from finishup.domain.result_delivery import mcp_delivery_bytes, reassemble_delivery
from finishup.ports.control import McpHostProfile
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import ReceiptResultModel

_HOSTS: tuple[McpHostProfile, ...] = ("generic", "codex", "claude", "cursor")
_FORMATS = ("json", "markdown", "text")
# Small enough that each receipt below is cut into several pages, as a long one is at the
# hosts' real budget; within the page model's own bounds.
_SMALL_BUDGET = 2_500
_WRITER = "wri_00000000-0000-4000-8000-000000000097"


def _text(result: object) -> str:
    content = cast(list[object], getattr(result, "content"))
    return cast(str, getattr(content[0], "text"))


def _live_gap(wire: dict[str, Any]) -> dict[str, Any]:
    document = cast(dict[str, Any], wire["document"])
    (gap,) = (gap for gap in document["gaps"] if gap["code"] == OUTSIDE_READS_NOT_LISTED_GAP)
    return cast(dict[str, Any], gap)


def _assert_says_the_number(wire: dict[str, Any], output_format: str) -> None:
    """``wire`` (a receipt result) says how many, as its format carries it."""

    if output_format == "json":
        gap = _live_gap(wire)
        assert gap["kept_back"] == _KEPT.as_wire()
        assert str(gap["detail"]).startswith(_COUNT_LINE + " ")
        assert kept_back_from_wire(cast(dict[str, JsonValue], wire["document"])) == _KEPT
    else:
        assert wire["document"] is None
        assert _COUNT_LINE in cast(str, wire["human_text"])


@pytest.mark.parametrize("host", _HOSTS)
@pytest.mark.parametrize("output_format", _FORMATS)
def test_an_unpaged_receipt_says_how_many_on_both_channels(
    host: McpHostProfile, output_format: str
) -> None:
    wire = kept_back_receipt_result(output_format)
    result = bridge.result_from_public_model(
        ReceiptResultModel.model_validate(wire), host_profile=host
    )
    assert result.isError is False
    structured = cast(dict[str, Any], result.structuredContent)
    assert structured == wire
    _assert_says_the_number(structured, output_format)
    text = _text(result)
    # The text channel is the receipt's canonical JSON for every host, never the compact summary.
    assert text == canonical_encode(cast(JsonValue, wire)).decode("utf-8")
    assert json.loads(text) == structured
    assert _COUNT_LINE in text
    if output_format == "json":
        assert '"kept_back":{"declared_tests":1,"task_inputs":3}' in text


def _pages(wire: dict[str, Any]) -> list[dict[str, JsonValue]]:
    """``wire`` cut into the pages the service gives an agent: the first from ``receipt``, the
    rest from ``status`` continuations naming the previous page's handle."""

    pages: list[dict[str, JsonValue]] = []
    position = 0
    while True:
        page = page_result(
            cast(dict[str, JsonValue], wire),
            method="receipt",
            selector={"request_id": wire["request_id"]},
            writer_id=_WRITER,
            sink="agent_context",
            position=position,
        )
        pages.append(page)
        cursor = page["next_cursor"]
        if cursor is None:
            return pages
        position = decode_handle(cast(str, cursor)).position


@pytest.mark.parametrize("host", _HOSTS)
@pytest.mark.parametrize("output_format", _FORMATS)
def test_a_paged_receipt_says_how_many_once_reassembled(
    monkeypatch: pytest.MonkeyPatch, host: McpHostProfile, output_format: str
) -> None:
    monkeypatch.setattr(delivery_module, "HOST_RESULT_BUDGET_BYTES", _SMALL_BUDGET)
    wire = kept_back_receipt_result(output_format)
    assert mcp_delivery_bytes(cast(dict[str, JsonValue], wire)) > _SMALL_BUDGET
    pages = _pages(wire)
    assert len(pages) > 1
    delivered: list[dict[str, Any]] = []
    for page in pages:
        result = bridge.result_from_public_model(
            ReceiptResultModel.model_validate(page), host_profile=host
        )
        assert result.isError is False
        assert result.structuredContent == page
        # Each page's text is its canonical JSON with the handle first: what the agent reads.
        text = _text(result)
        assert text.startswith('{"next_cursor":')
        parsed = cast(dict[str, Any], json.loads(text))
        assert parsed == page
        delivered.append(parsed)
    # Reassembled from the text the agent read, the receipt is the one the service built, and
    # says how many in the place its format carries it.
    rebuilt = reassemble_delivery(delivered)
    assert {key: value for key, value in rebuilt.items() if key != "privacy_projection"} == {
        key: value for key, value in wire.items() if key != "privacy_projection"
    }
    _assert_says_the_number(cast(dict[str, Any], rebuilt), output_format)
