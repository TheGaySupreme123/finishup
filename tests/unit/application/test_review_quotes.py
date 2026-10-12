"""Reviewer quote proof against provider-bound text (issue #976, TB4 tb4v1)."""

from __future__ import annotations

import json

import pytest

from yoetz.application.review_quotes import REDACTION_MARKER, prove_quote


def test_exact_substring_is_returned_unchanged() -> None:
    assert prove_quote("sent row", ("a sent row here",)) == "sent row"


def test_reflowed_whitespace_returns_the_verbatim_sent_span() -> None:
    sent = "row: first line\n   second line end"
    assert prove_quote("first line second line", (sent,)) == "first line\n   second line"


def test_quote_from_a_json_row_matches_its_decoded_text() -> None:
    # The packet carries ledger rows as JSON documents: the reviewer reads the decoded statement,
    # with a typographic apostrophe and a real newline, while the row holds escapes.
    row = json.dumps(
        {"payload": {"statement": "The report’s annotations\ncame from a custom model."}},
        ensure_ascii=True,
    )
    assert "\\u2019" in row
    proven = prove_quote("The report's annotations came from a custom model", (row,))
    assert proven == "The report’s annotations\ncame from a custom model"


def test_quote_copied_with_json_escapes_matches() -> None:
    sent = 'status: "ok" for run 3'
    assert prove_quote('status: \\"ok\\" for run 3', (sent,)) == 'status: "ok" for run 3'


@pytest.mark.parametrize(
    "placeholder", ["[REDACTED]", "[redacted]", "<redacted>", "[redacted value]"]
)
def test_redaction_placeholder_matches_only_yoetz_marker(placeholder: str) -> None:
    sent = f"token = {REDACTION_MARKER} + suffix"
    assert prove_quote(f"token = {placeholder} + suffix", (sent,)) == sent


def test_placeholder_does_not_match_unredacted_text() -> None:
    # A placeholder is not a wildcard: it must line up with a real marker in the sent text.
    assert prove_quote("token = [redacted] + suffix", ("token = abc + suffix",)) is None


def test_placeholder_only_quote_proves_nothing() -> None:
    assert prove_quote("[REDACTED]", (f"x {REDACTION_MARKER} y",)) is None
    assert prove_quote(" [REDACTED]  ", (f"x  {REDACTION_MARKER}   y",)) is None
    assert prove_quote("<redacted>", (f"x {REDACTION_MARKER} y",)) is None


@pytest.mark.parametrize(
    "quote",
    [
        "invented quote",
        "THE REPORT",  # case is never folded
        "first ... line",  # elision is never accepted
        "firstline",  # characters are never skipped
    ],
)
def test_unproven_quotes_are_rejected(quote: str) -> None:
    assert prove_quote(quote, ("the report first line",)) is None


def test_no_text_proves_nothing() -> None:
    assert prove_quote("anything", ()) is None
    assert prove_quote("", ("anything",)) is None


@pytest.mark.parametrize(
    ("quote", "sent"),
    [
        ("x2 y", "x\u00b2 y"),  # superscript digit is not the digit
        ("fix", "\ufb01x"),  # ligature is not two letters
        ("A1", "\uff21\uff11"),  # fullwidth forms are not ASCII
    ],
)
def test_compatibility_forms_are_never_folded(quote: str, sent: str) -> None:
    assert prove_quote(quote, (sent,)) is None


@pytest.mark.parametrize("control", ["\x00", "\u202e", "\u200b"])
def test_span_with_control_or_format_characters_is_not_admitted(control: str) -> None:
    row = json.dumps({"statement": f"value{control} is  wrong"})
    assert prove_quote(f"value{control} is wrong", (row,)) is None


def test_lone_surrogate_in_sent_json_is_not_admitted() -> None:
    row = '{"statement": "bad \\ud800 text  here"}'
    assert prove_quote("bad \ud800 text here", (row,)) is None


def test_span_ending_on_a_collapsed_space_takes_no_extra_character() -> None:
    sent = f"key = {REDACTION_MARKER}   next"
    assert prove_quote("key = [redacted]", (sent,)) == f"key = {REDACTION_MARKER}"


def test_large_rows_are_searched_in_bounded_time() -> None:
    import time

    rows = tuple(("word " * 200_000) + str(number) for number in range(5))
    started = time.monotonic()
    assert prove_quote("word  word 4", rows) == "word word 4"
    assert time.monotonic() - started < 5


def test_many_adjacent_placeholders_match_in_linear_time() -> None:
    import time

    sent = f"{REDACTION_MARKER} " * 40 + "y"
    started = time.monotonic()
    assert prove_quote("[redacted] " * 12 + "x", (sent,)) is None
    assert prove_quote("[redacted] " * 12 + "y", (sent,)) == f"{REDACTION_MARKER} " * 11 + (
        f"{REDACTION_MARKER} y"
    )
    # Past the placeholder cap a quote is matched exactly or not at all.
    assert prove_quote("[redacted] " * 40 + "x", (sent,)) is None
    assert time.monotonic() - started < 1


@pytest.mark.parametrize(
    "quote",
    [
        "[redacted] " * 2000,
        "[redacted] a " * 2000,
        "[redacted]  " * 16 + "zz",
        "[REDACTED] " * 15 + "abc q",
        '\\" [ redacted ] \\n  ' * 500 + "abc",
        "[redacted" * 3000 + " abc",
        "[ " * 5000 + "redacted",
    ],
)
def test_reviewer_controlled_quotes_cannot_hang_a_check(quote: str) -> None:
    # A reviewer-controlled quote is matched against large packets in bounded, near-linear time:
    # many placeholders, whitespace runs, escapes, and unclosed brackets never backtrack.
    import time

    packets = (
        "abc [REDACTED] " * 5000 + "x",
        f"{REDACTION_MARKER} " * 20000,
        json.dumps({"a": f"{REDACTION_MARKER} " * 2000}),
    )
    started = time.monotonic()
    prove_quote(quote, packets)
    assert time.monotonic() - started < 1


def test_adjacent_markers_without_spaces_match() -> None:
    sent = f"a{REDACTION_MARKER}{REDACTION_MARKER}b"
    assert prove_quote("a [redacted] [redacted] b", (sent,)) == sent


def test_json_row_match_returns_decoded_text_of_that_row() -> None:
    row = json.dumps({"s": "line one\nline two \u00e9"})
    span = prove_quote("line one line two \u00e9", (row,))
    assert span == "line one\nline two \u00e9"
    decoded = json.loads(row)["s"]
    assert span in decoded
