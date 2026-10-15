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


def test_every_name_behind_a_path_prefix_is_withheld_top_level_and_extensionless_too() -> None:
    """#1073 review P2-1: ``./``, absolute, ``~``, ``$VAR``, ``file://``, ``//`` and ``/./``."""

    cases = {
        "vocab_table": (
            "Loads ./vocab_table now.",
            "Loads ././vocab_table now.",
            "Loads /Users/u/repo/vocab_table now.",
            "Loads /Users/u//repo/./vocab_table now.",
            "Loads ~/repo/vocab_table now.",
            "Loads ~u/repo/vocab_table now.",
            "Loads $PWD/vocab_table now.",
            "Loads ${HOME}/repo/vocab_table now.",
            "Loads file:///Users/u/repo/vocab_table now.",
            "Loads 'vocab_table' now.",
            "Loads `./vocab_table` now.",
            'Loads "/Users/u/My Project/vocab_table" now.',
            'Loads "~/My Project/vocab_table" now.',
        ),
        "artifacts/english_words.npz": (
            "Loads file:///Users/u/repo/artifacts/english_words.npz now.",
            "Loads /Users/u/repo//artifacts/english_words.npz now.",
            "Loads ./artifacts/./english_words.npz now.",
            "Loads artifacts//english_words.npz now.",
            "Loads $PWD/artifacts/english_words.npz now.",
            "Loads ${PWD}/artifacts/english_words.npz now.",
            "Loads ~/repo/artifacts/english_words.npz now.",
            'Loads "$PWD/artifacts/english_words.npz" now.',
            'Loads "~/My Project/artifacts/english_words.npz" now.',
        ),
    }
    for path, texts in cases.items():
        stem = path.rsplit("/", 1)[-1].split(".")[0]
        for text in texts:
            shown = withheld_text(text, (_named(path),))
            assert shown == f"Loads {WITHHELD} now.", (text, shown)
            assert stem not in shown


def test_plain_words_and_other_relative_directories_stay_readable() -> None:
    # A top-level name without an extension is a path only behind a prefix or in quotes.
    excerpt = _named("Summary")
    text = "Summary\nThe Summary has 2 findings; ./Summary is the file."
    assert withheld_text(text, (excerpt,)) == (
        f"Summary\nThe Summary has 2 findings; {WITHHELD} is the file."
    )
    for path, text in (
        ("vocab_table", "Loads vocab_table and my_vocab_table and ./vocab_table.bak now."),
        ("artifacts/wordlist", "Loads wordlist and 'wordlist' now."),
        ("artifacts/english_words.npz", "Loads ../repo/artifacts/english_words.npz now."),
        ("artifacts/english_words.npz", 'Loads "./My Project/artifacts/english_words.npz" now.'),
    ):
        assert withheld_text(text, (_named(path),)) == text, text


def test_span_search_stays_linear_on_adversarial_prose() -> None:
    """#1073 review P3: participant prose reaches this pattern on the service event loop."""

    import time

    excerpts = tuple(_named(f"artifacts/m{index}.npz") for index in range(8)) + (
        _named("vocab_table"),
    )
    for text in (
        "/," * 16_384,
        ",/" * 16_384,
        " ./" * 10_000,
        " ~/" * 10_000,
        " $A/" * 8_000,
        '"' + "/a" * 16_000,
        " " + "/" * 32_000,
    ):
        started = time.perf_counter()
        withheld_text(text, excerpts, max_chars=32_768)
        # Quadratic search took about 7 s on 32 K characters before the bound; linear takes
        # well under a second. The bound is generous so a loaded runner cannot flake it.
        assert time.perf_counter() - started < 3.0, text[:8]


def test_a_dot_slash_with_empty_or_dot_segments_is_still_the_same_file() -> None:
    """#1073 review round 2, P2-1: ``.//name`` (as BSD and macOS ``find ./`` print it)."""

    cases = {
        "artifacts/model.npz": (
            "Loads .//artifacts/model.npz now.",
            "Loads ././/artifacts/model.npz now.",
            "Loads .//./artifacts/model.npz now.",
            "Loads './/artifacts/model.npz' now.",
            'Loads ".//artifacts/model.npz" now.',
            "Loads `.//artifacts/model.npz` now.",
            "Loads .//model.npz now.",
        ),
        "vocab_table": ("Loads .//vocab_table now.", "Loads `././/vocab_table` now."),
    }
    for path, texts in cases.items():
        for text in texts:
            assert withheld_text(text, (_named(path),)) == f"Loads {WITHHELD} now.", text


def test_names_glued_after_a_brace_dollar_or_tilde_are_withheld() -> None:
    """#1073 review round 2: round 1 withheld these; the widened boundary must not lose them."""

    excerpt = _named("artifacts/a.npz")
    for text, expected in (
        ("Loads ${ROOT}artifacts/a.npz now.", f"Loads ${{ROOT}}{WITHHELD} now."),
        ('Loads f"{root}artifacts/a.npz" now.', f'Loads f"{{root}}{WITHHELD}" now.'),
        ("Loads $ROOT/artifacts/a.npz now.", f"Loads {WITHHELD} now."),
        ("Loads ~artifacts/a.npz now.", f"Loads {WITHHELD} now."),
    ):
        assert withheld_text(text, (excerpt,)) == expected, text


def test_an_absolute_path_ending_in_a_names_last_component_is_withheld() -> None:
    # Absolute prefixes match the last component, so a list or a glued delimiter cannot hide
    # the name, and a relative path in another directory stays readable.
    excerpt = _named("artifacts/wordlist")
    assert withheld_text("Reads /x/y/wordlist.", (excerpt,)) == f"Reads {WITHHELD}."
    assert withheld_text("Reads ./x/wordlist.", (excerpt,)) == "Reads ./x/wordlist."
    model = _named("artifacts/a.npz")
    assert withheld_text("files=/r/artifacts/a.npz,/r/b.npz", (model,)) == (
        f"files={WITHHELD},/r/b.npz"
    )
    assert withheld_text("PYTHONPATH=/r/x/a.npz:/r/y", (model,)) == (f"PYTHONPATH={WITHHELD}:/r/y")
    assert withheld_text("Reads /r/a.npz.d/x and (/r/a.npz).", (model,)) == (
        f"Reads /r/a.npz.d/x and ({WITHHELD})."
    )


def test_one_search_per_leaf_whatever_the_number_of_names() -> None:
    """#1073 review round 2, P3: names x leaves cost 36 s for 512 names on one 32 K leaf."""

    import time

    from yoetz.application.receipt_projection import (
        _NameMatcher,  # pyright: ignore[reportPrivateUsage]
    )

    names = [f"dir{index}/sub/file_{index}.npz" for index in range(512)]
    matcher = _NameMatcher(names)
    for text in (
        ":/" * 16_384,
        " ".join(f"/x/file_{index}.npz" for index in range(512)) + ":/" * 8_000,
        "file_1.npz " * 3_000,
        # Round 3: quoted interiors are searched again, and a ``:`` may sit inside a segment.
        "`'\"" * 10_000,
        "/" + "a:" * 16_000,
        ("`" + "/x/file_1.npz " * 3 + "/x/file_2.npz`") * 600,
    ):
        started = time.perf_counter()
        matcher.paths_in(text)
        assert time.perf_counter() - started < 3.0, text[:8]
    assert matcher.paths_in("Reads /q/file_7.npz and dir9/sub/file_9.npz.") == {
        "dir7/sub/file_7.npz",
        "dir9/sub/file_9.npz",
    }
    assert matcher.paths_in("Reads file_7 and x/dir7/sub/file_7.npz.") == set()


def test_every_path_in_a_quoted_token_is_found_not_only_the_last() -> None:
    """#1073 review round 3, T1: one quoted token can hold several paths."""

    from yoetz.application.receipt_projection import (
        _NameMatcher,  # pyright: ignore[reportPrivateUsage]
    )

    matcher = _NameMatcher(["artifacts/a.npz", "data/b.npz"])
    for text in (
        "Ran `/usr/bin/cmp /home/u/repo/data/b.npz /home/u/repo/artifacts/a.npz` first.",
        'Ran "/home/u/repo/data/b.npz and /home/u/repo/artifacts/a.npz" first.',
        "Ran '~/repo/data/b.npz ~/repo/artifacts/a.npz' first.",
    ):
        assert matcher.paths_in(text) == {"artifacts/a.npz", "data/b.npz"}, text
        # With only the earlier name withheld (the requester published the last one), the
        # earlier one is still replaced inside the quotes and the published one stays.
        shown = withheld_text(text, (_named("data/b.npz"),))
        assert "b.npz" not in shown and "a.npz" in shown and WITHHELD in shown, shown


def test_colons_inside_a_path_or_a_port_do_not_hide_the_name() -> None:
    """#1073 review round 3: a ``:`` stops a prefix only where another path starts."""

    excerpt = _named("artifacts/a.npz")
    for text, expected in (
        ("Fetched http://localhost:8000/r/artifacts/a.npz.", f"Fetched http:{WITHHELD}."),
        ("Read /r/dir:x/artifacts/a.npz.", f"Read {WITHHELD}."),
        ("PYTHONPATH=/r/x/a.npz:/r/y", f"PYTHONPATH={WITHHELD}:/r/y"),
        ("files=/r/artifacts/a.npz,/r/b.npz", f"files={WITHHELD},/r/b.npz"),
    ):
        assert withheld_text(text, (excerpt,)) == expected, text
