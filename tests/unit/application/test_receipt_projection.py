"""Agent-context receipt name spans: span replacement and the omitted-pointer bound."""

from __future__ import annotations

from yoetz.application.receipt_projection import (
    WITHHELD,
    ReceiptExcerpt,
    bounded_omitted_pointers,
    withheld_text,
)
from yoetz.protocol.models import MAX_PROJECTION_CONTENT_LEAVES


def _excerpt(path: str, *spellings: str) -> ReceiptExcerpt:
    return ReceiptExcerpt("/human_text/@repository_name/0", "/human_text", path, spellings)


def test_only_the_name_span_is_withheld() -> None:
    text = 'Summary\nThe deliverable loads "a/b.npz" and a/b.npz; 2 files.'
    shown = withheld_text(text, (_excerpt("a/b.npz", '"a/b.npz"', "a/b.npz"),))
    assert shown == f"Summary\nThe deliverable loads {WITHHELD} and {WITHHELD}; 2 files."
    assert withheld_text(text, ()) == text


def test_omitted_pointers_coalesce_deterministically_and_never_drop_one() -> None:
    small = ("/b", "/a/1", "/a/0", "/a/0")
    assert bounded_omitted_pointers(small) == ("/a/0", "/a/1", "/b")
    many = [f"/document/sections/{s}/items/{i}" for s in range(3) for i in range(300)]
    many.append("/document/gaps/0/detail")
    bounded = bounded_omitted_pointers(many)
    assert len(bounded) <= MAX_PROJECTION_CONTENT_LEAVES
    assert list(bounded) == sorted(set(bounded), key=str.encode)
    assert bounded == bounded_omitted_pointers(list(reversed(many)))
    for pointer in many:
        assert any(pointer == kept or pointer.startswith(kept + "/") for kept in bounded)
    assert "/document/gaps/0/detail" in bounded


def test_a_distinctive_basename_is_withheld_but_never_inside_a_longer_name() -> None:
    excerpt = _excerpt("artifacts/a.npz", '"artifacts/a.npz"', "artifacts/a.npz", "a.npz")
    text = "Reads a.npz, data.npz, a.npz.bak and x/a.npz; artifacts/a.npz."
    assert withheld_text(text, (excerpt,)) == (
        f"Reads {WITHHELD}, data.npz, a.npz.bak and x/a.npz; {WITHHELD}."
    )


def _named(path: str) -> ReceiptExcerpt:
    from yoetz.application.receipt_projection import (
        _spellings,  # pyright: ignore[reportPrivateUsage]
    )

    return ReceiptExcerpt("/human_text/@repository_name/0", "/human_text", path, _spellings(path))


def test_dot_slash_quoted_and_absolute_spellings_withhold_the_whole_token() -> None:
    """r3 F2: ``./`` (any number, quoted or not) and an absolute spelling are the same file."""

    excerpt = _named("artifacts/english_words.npz")
    for text in (
        "Loads ./artifacts/english_words.npz at start.",
        'Loads "./artifacts/english_words.npz" at start.',
        "Loads ././artifacts/english_words.npz at start.",
        "Loads '/home/u/repo/artifacts/english_words.npz' at start.",
        "Loads `artifacts/english_words.npz` at start.",
    ):
        shown = withheld_text(text, (excerpt,))
        assert "english_words" not in shown, text
        assert shown.startswith("Loads ") and shown.endswith(" at start."), shown
        assert "./" not in shown and "/home" not in shown


def test_different_files_and_case_variants_stay_readable() -> None:
    excerpt = _named("artifacts/english_words.npz")
    for text in (
        "x/artifacts/english_words.npz",
        "my_english_words.npz",
        "english_words.npz.bak",
        "data.npz",
        # Exact comparison: on a case-sensitive filesystem this is a different file.
        "Artifacts/English_words.npz",
    ):
        assert withheld_text(text, (excerpt,)) == text


def test_expansion_is_bounded_visibly_without_splitting_a_token() -> None:
    """r3 F3: replacing short names with the longer token cannot overflow a field or item."""

    from yoetz.application.receipt_projection import HUMAN_TEXT_MAX_CHARS
    from yoetz.domain.privacy import MAX_EGRESS_ITEM_BYTES
    from yoetz.protocol.canonical import canonical_encode

    excerpt = _named("artifacts/english_ngrams.npz")
    text = "english_ngrams.npz " * 400
    for max_chars in (HUMAN_TEXT_MAX_CHARS, None):
        shown = withheld_text(text, (excerpt,), max_chars=max_chars)
        assert "english_ngrams" not in shown
        assert len(canonical_encode(shown)) <= MAX_EGRESS_ITEM_BYTES
        assert len(shown) <= (max_chars or max(len(text), 4096))
        body, marker = shown.rsplit(" [receipt text truncated after withholding: ", 1)
        assert marker.endswith(" characters not shown]")
        # Only whole tokens survive the cut.
        assert body.replace(WITHHELD, "").strip() == ""
    # A short text that fits is never truncated.
    assert withheld_text("Reads english_ngrams.npz.", (excerpt,)) == f"Reads {WITHHELD}."


def test_quoted_absolute_paths_with_spaces_are_withheld_whole() -> None:
    """R3-F2: quotes bound the token, so a directory with spaces is still one path."""

    excerpt = _named("artifacts/english_words.npz")
    for quote in ('"', "'", "`"):
        text = f"Loads {quote}/Users/u/My Project/artifacts/english_words.npz{quote} at start."
        assert withheld_text(text, (excerpt,)) == f"Loads {WITHHELD} at start.", quote
    # Quote-bounded, so distinct names and suffixes inside quotes stay readable.
    for text in (
        '"/Users/u/My Project/x/artifacts/english_words.npz.bak"',
        '"x/artifacts/english_words.npz"',
        '"/Users/u/My Project/artifacts/English_words.npz"',
        'Say "hello world" twice.',
    ):
        assert withheld_text(text, (excerpt,)) == text, text
