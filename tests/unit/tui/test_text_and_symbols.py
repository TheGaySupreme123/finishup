"""Width-aware text helpers and the certainty vocabulary."""

from __future__ import annotations

import pytest

from finishup.tui.symbols import Level, style_for, symbol_for
from finishup.tui.text import ELLIPSIS, middle_truncate, pad_columns, truncate, wrap


def test_every_certainty_level_has_a_distinct_symbol_and_style() -> None:
    symbols = [symbol_for(level) for level in Level]
    assert len(set(symbols)) == len(symbols)
    assert set(symbols) == {"›", "•", "✓", "!", "■", "○"}
    assert len({style_for(level) for level in Level}) == len(list(Level))


def test_truncate_marks_the_loss_and_never_exceeds_the_width() -> None:
    assert truncate("abcdef", 10) == "abcdef"
    assert truncate("abcdef", 4) == "abc" + ELLIPSIS
    assert len(truncate("abcdef", 4)) == 4
    assert truncate("abcdef", 0) == ""


@pytest.mark.parametrize("width", [3, 8, 16, 30])
def test_middle_truncate_keeps_head_and_tail_within_the_width(width: int) -> None:
    path = "/srv/projects/finishup/src/finishup/cli/app.py"
    result = middle_truncate(path, width)
    assert len(result) == width
    assert ELLIPSIS in result
    # The final component is what identifies a path to a reader.
    if width >= 16:
        assert result.endswith("app.py")
    assert result.startswith(path[0])


def test_middle_truncate_leaves_short_values_alone() -> None:
    assert middle_truncate("~/p/finishup", 20) == "~/p/finishup"


def test_wrap_breaks_on_words_and_hard_splits_only_when_it_must() -> None:
    assert wrap("one two three", 9) == ("one two", "three")
    long_digest = "a" * 25
    assert wrap(long_digest, 10) == ("a" * 10, "a" * 10, "a" * 5)
    assert wrap("", 10) == ("",)
    assert wrap("anything", 0) == ()


def test_wrap_never_produces_a_line_wider_than_requested() -> None:
    text = "Trust the exact approved-check policy digest 7f8a92bd0011deadbeef"
    for width in range(8, 40):
        assert all(len(line) <= width for line in wrap(text, width))


def test_pad_columns_aligns_labels_without_trailing_whitespace() -> None:
    rows = pad_columns((("Project", "~/p"), ("Codex", "connected")), gap=2)
    assert rows == ("Project  ~/p", "Codex    connected")
    assert all(line == line.rstrip() for line in rows)
