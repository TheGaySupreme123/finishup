"""A receipt's closing "Workspace evidence" section fits the human_text bound (ADR-051, D4).

The section is rendered with the rest of the text, its room reserved first, so a receipt whose
other sections already fill the 32,768-character wire bound still ends with it whole and still
validates for delivery. Appending it after the bound was applied made such a receipt
undeliverable.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from finishup.domain.receipts import (
    ReceiptDocument,
    client_attested_receipt_block,
    receipt_document_from_json,
    render_receipt_human,
    workspace_provenance_unknown_block,
)
from finishup.domain.workspace_provenance import (
    SESSION_OPENING_UNREADABLE,
    WORKSPACE_PROVENANCE_REASONS,
)
from finishup.protocol.errors import ProtocolValueError

_HUMAN_TEXT_MAX = 32_768
_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000091"
_FIXTURE = Path(__file__).parents[3] / "fixtures" / "receipts" / "unresolved-findings.case.json"


def _document() -> ReceiptDocument:
    case = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    return receipt_document_from_json(
        case["expected"]["variants"]["mixed_open_responses"]["receipt_document"]
    )


def _padded(document: ReceiptDocument, *, markdown: bool, length: int) -> ReceiptDocument:
    """``document`` with its first section's body sized so its rendering is ``length`` long."""

    first = document.sections[0]

    def with_body(size: int) -> ReceiptDocument:
        return replace(document, sections=(replace(first, body="x" * size), *document.sections[1:]))

    base = len(render_receipt_human(with_body(1), markdown=markdown))
    padded = with_body(1 + length - base)
    assert len(render_receipt_human(padded, markdown=markdown)) == length
    return padded


def _trailers(markdown: bool) -> dict[str, str]:
    return {
        "unknown": workspace_provenance_unknown_block(
            markdown=markdown, reason=SESSION_OPENING_UNREADABLE
        ),
        # The longest section a lasting cause ends with: every other one fits where it does.
        "unknown_lasting": max(
            (
                workspace_provenance_unknown_block(markdown=markdown, reason=reason)
                for reason in WORKSPACE_PROVENANCE_REASONS
                if reason != SESSION_OPENING_UNREADABLE
            ),
            key=len,
        ),
        "attested": client_attested_receipt_block(_SERVICE_ID, markdown=markdown),
        "attested_hook": client_attested_receipt_block(
            _SERVICE_ID, markdown=markdown, hook_observed=True
        ),
    }


@pytest.mark.parametrize("markdown", [False, True], ids=["text", "markdown"])
@pytest.mark.parametrize("section", ["unknown", "unknown_lasting", "attested", "attested_hook"])
@pytest.mark.parametrize("length", [32_400, 32_700, _HUMAN_TEXT_MAX])
def test_a_receipt_at_the_bound_still_ends_with_its_whole_closing_section(
    markdown: bool, section: str, length: int
) -> None:
    """Rendered without the section, the receipt is ``length`` long and fits; with it, the text
    is either whole (the section has room) or has its other sections shortened, never the closing
    one, and the whole text still fits."""

    trailer = _trailers(markdown)[section]
    document = _padded(_document(), markdown=markdown, length=length)

    rendered = render_receipt_human(document, markdown=markdown, trailer=trailer)

    assert len(rendered) <= _HUMAN_TEXT_MAX
    assert rendered.endswith("\n\n" + trailer)
    assert rendered.count(trailer) == 1
    if length + len("\n\n" + trailer) <= _HUMAN_TEXT_MAX:
        assert rendered == render_receipt_human(document, markdown=markdown) + "\n\n" + trailer
    else:
        assert "truncated at 32768 characters" in rendered
        assert "shortened sections: Summary" in rendered


@pytest.mark.parametrize("markdown", [False, True], ids=["text", "markdown"])
@pytest.mark.parametrize("section", ["unknown", "unknown_lasting", "attested", "attested_hook"])
def test_an_overlong_receipt_is_cut_before_its_closing_section(
    markdown: bool, section: str
) -> None:
    trailer = _trailers(markdown)[section]
    first = _document().sections[0]
    document = replace(
        _document(),
        sections=(replace(first, body="x" * 32_768), *_document().sections[1:]),
    )

    rendered = render_receipt_human(document, markdown=markdown, trailer=trailer)

    assert len(rendered) <= _HUMAN_TEXT_MAX
    assert rendered.endswith("holds every section in full.]\n\n" + trailer)


@pytest.mark.parametrize("markdown", [False, True], ids=["text", "markdown"])
@pytest.mark.parametrize("section", ["unknown", "unknown_lasting", "attested", "attested_hook"])
def test_a_receipt_with_room_gains_the_section_and_nothing_else(
    markdown: bool, section: str
) -> None:
    trailer = _trailers(markdown)[section]
    document = _document()
    plain = render_receipt_human(document, markdown=markdown)

    assert render_receipt_human(document, markdown=markdown, trailer=trailer) == (
        plain + "\n\n" + trailer
    )
    # The largest receipt that still has room is rendered whole too.
    room = _HUMAN_TEXT_MAX - len("\n\n" + trailer)
    fitting = _padded(document, markdown=markdown, length=room)
    rendered = render_receipt_human(fitting, markdown=markdown, trailer=trailer)
    assert len(rendered) == _HUMAN_TEXT_MAX
    assert rendered == render_receipt_human(fitting, markdown=markdown) + "\n\n" + trailer


@pytest.mark.parametrize("trailer", ["", "x" * 2_049])
def test_a_closing_section_that_is_empty_or_too_long_is_refused(trailer: str) -> None:
    with pytest.raises(ProtocolValueError, match="invalid_receipt_document"):
        render_receipt_human(_document(), markdown=False, trailer=trailer)
