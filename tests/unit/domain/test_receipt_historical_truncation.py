"""A long receipt keeps its historical section through the human_text cut (issue #1017)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import tests.unit.kernel.test_receipt_builder as receipt_tests

from yoetz.domain.receipts import HISTORICAL_GAPS_SECTION_TITLE, render_receipt_human

_historical_receipt: Any = getattr(receipt_tests, "_historical_receipt")


def test_a_long_receipt_still_shows_its_cleared_gaps() -> None:
    receipt = _historical_receipt(historical=True)
    long_sections = tuple(replace(section, body="x" * 20_000) for section in receipt.sections)
    receipt = replace(receipt, sections=long_sections)

    for markdown in (True, False):
        text = render_receipt_human(receipt, markdown=markdown)
        assert len(text) <= 32_768
        assert "truncated at 32768 characters" in text
        assert HISTORICAL_GAPS_SECTION_TITLE in text
        assert "cleared at frontier 1; no action needed." in text
