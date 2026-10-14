"""Coverage for the bounded heading-topic catalog behind read_guidance."""

from __future__ import annotations

from pathlib import Path

import pytest

from yoetz.mcp import resources
from yoetz.mcp.resources import MAX_GUIDANCE_PAGE_SIZE
from yoetz.protocol.guidance_uris import GUIDANCE_TOPIC_URIS

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
