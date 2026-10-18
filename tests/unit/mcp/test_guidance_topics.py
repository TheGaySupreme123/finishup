"""Coverage for the bounded heading-topic catalog behind read_guidance."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from finishup.mcp import resources
from finishup.mcp.resources import MAX_GUIDANCE_PAGE_SIZE
from finishup.protocol.guidance_uris import GUIDANCE_TOPIC_URIS

_ROOT = Path(__file__).resolve().parents[3]


def _read_canonical_resource(logical_name: str) -> bytes:
    return (_ROOT / logical_name).read_bytes()


def test_every_catalogued_heading_is_a_bounded_utf8_topic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every legacy procedure remains reachable without loading its parent document."""

    monkeypatch.setattr(
        resources,
        "read_verified_resource",
        _read_canonical_resource,
    )
    resources._topic_resource.cache_clear()  # pyright: ignore[reportPrivateUsage]

    assert GUIDANCE_TOPIC_URIS
    for uri in GUIDANCE_TOPIC_URIS:
        topic = resources.resource_for_uri(uri)
        payload = topic.bytes
        assert topic.uri == uri
        assert payload.startswith(b"#")
        assert 0 < len(payload) <= MAX_GUIDANCE_PAGE_SIZE
    for uri in resources._FOCUSED_TOPIC_URIS:  # pyright: ignore[reportPrivateUsage]
        topic = resources.resource_for_uri(uri)
        assert 0 < len(topic.bytes) <= MAX_GUIDANCE_PAGE_SIZE


def test_catalogued_topic_has_one_max_sized_page(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host can request any topic at the protocol maximum without an oversized-page retry."""

    monkeypatch.setattr(
        resources,
        "read_verified_resource",
        _read_canonical_resource,
    )
    resources._topic_resource.cache_clear()  # pyright: ignore[reportPrivateUsage]

    for uri in GUIDANCE_TOPIC_URIS:
        page = resources.read_resource_page(uri, page_size=MAX_GUIDANCE_PAGE_SIZE)
        assert page.resource.uri == uri
        assert page.page_count == 1
        assert page.complete
        assert page.continuation is None
    for uri in resources._FOCUSED_TOPIC_URIS:  # pyright: ignore[reportPrivateUsage]
        page = resources.read_resource_page(uri, page_size=MAX_GUIDANCE_PAGE_SIZE)
        assert page.page_count == 1
        assert page.complete


# A backticked bare anchor such as `#publish-shapes`: not part of a longer URI, and not the text of
# a Markdown link whose target names its page. `#anchor` is the generic word, not an anchor.
_BARE_ANCHOR = re.compile(r"(?<![\w/.:])`#([a-z0-9][a-z0-9-]*)`(?!\]\()")
_GENERIC_ANCHOR_WORDS = frozenset({"anchor"})


def test_a_bare_anchor_names_a_topic_of_its_own_page() -> None:
    """n7 RC3 (#1103): a bare anchor reads against the page it is written on.

    The operating card wrote `#publish-shapes` (a request-templates topic) between two other
    pages' URIs; 42 reads resolved it against the card or a neighbour and were refused. Every bare
    anchor must therefore be a catalogued topic of the page that writes it; any other anchor is
    written as its full topic URI.
    """

    stray: list[str] = []
    for path in sorted((_ROOT / "guidance").glob("*.md")):
        page = f"finishup://guidance/{path.name}"
        for anchor in _BARE_ANCHOR.findall(path.read_text(encoding="utf-8")):
            if (
                anchor not in _GENERIC_ANCHOR_WORDS
                and f"{page}#{anchor}" not in GUIDANCE_TOPIC_URIS
            ):
                stray.append(f"{path.name}#{anchor}")
    assert stray == []
