"""Advertised tool schemas name the current product; the catalogue bytes stay frozen (ADR-048)."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import cast

from finishup.mcp.descriptors import TOOL_DESCRIPTORS
from finishup.protocol.canonical import JsonValue


def _titles(value: JsonValue) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, item in cast(Mapping[str, JsonValue], value).items():
            if key == "title" and type(item) is str:
                yield item
            elif key not in {"const", "default", "enum", "examples"}:
                yield from _titles(item)
    elif isinstance(value, Sequence) and not isinstance(value, str):
        for item in cast(Sequence[JsonValue], value):
            yield from _titles(item)


def test_advertised_schema_titles_name_finishup_never_yoetz() -> None:
    renamed = 0
    for descriptors in TOOL_DESCRIPTORS.values():
        for descriptor in descriptors:
            for schema in (descriptor.input_schema, descriptor.output_schema):
                titles = list(_titles(cast(JsonValue, schema)))
                assert not [title for title in titles if title.startswith("Yoetz")]
                renamed += sum(title.startswith("FinishUP ") for title in titles)
    assert renamed


def test_the_catalogue_bundle_keeps_the_released_title_bytes() -> None:
    check = next(item for item in TOOL_DESCRIPTORS["policy"] if item.name == "check")
    catalog = list(_titles(cast(JsonValue, check.catalog_output_schema)))
    advertised = list(_titles(cast(JsonValue, check.output_schema)))
    # Released frontier 1.0.0 is byte-frozen with its pre-rename title; only the projection renames.
    assert "Yoetz frontier 1.0.0" in catalog
    assert "FinishUP frontier 1.0.0" in advertised
    assert sorted(title.replace("Yoetz ", "FinishUP ", 1) for title in catalog) == sorted(
        advertised
    )
