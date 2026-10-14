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
