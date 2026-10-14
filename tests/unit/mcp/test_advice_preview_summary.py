"""The MCP advice status text names a preview-policy skip directly (#1019 r3)."""

from __future__ import annotations

from yoetz.mcp.summaries import summary_for_status

_SENTENCE = "Background AI-powered advice skipped (advice_semantic_preview_required)"


def _envelope(gaps: list[str], *, in_coverage: bool = False) -> dict[str, object]:
    return {
        "view": "advice",
        "page": {"items": []},
        "gaps": [] if in_coverage else gaps,
        "coverage": {"known_gaps": gaps if in_coverage else []},
    }


def test_preview_skip_is_stated_in_the_advice_text() -> None:
    for in_coverage in (False, True):
        text = summary_for_status(
            _envelope(
                ["advice_semantic_preview_required", "advice_semantic_unavailable"],
                in_coverage=in_coverage,
            )
        )
        assert _SENTENCE in text
        assert "nothing was queued or sent" in text


def test_advice_text_without_the_skip_says_nothing_about_it() -> None:
    text = summary_for_status(_envelope(["advice_semantic_unavailable"]))
    assert "advice_semantic_preview_required" not in text
    assert "Status view: advice" in text
