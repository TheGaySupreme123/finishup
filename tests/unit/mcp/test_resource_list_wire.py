"""resources/list must decode in Codex's rmcp client (benchmark full3: 37 failed lists)."""

from __future__ import annotations

import json
from typing import cast

import anyio
from mcp import types

from yoetz.mcp import server as bridge


def _floats(value: object) -> list[float]:
    if isinstance(value, float):
        return [value]
    if isinstance(value, dict):
        mapping = cast(dict[str, object], value)
        return [found for item in mapping.values() for found in _floats(item)]
    if isinstance(value, list):
        items = cast(list[object], value)
        return [found for item in items for found in _floats(item)]
    return []


def test_resource_listing_carries_no_fractional_number() -> None:
    """rmcp built with serde_json arbitrary_precision rejects buffered floats such as 0.9.

    One float anywhere in the listing turns the whole result into rmcp's ``CustomResult`` and
    Codex reports ``Unexpected response type``; integers still decode.
    """

    resources = anyio.run(bridge.list_resources)
    assert resources
    wire = types.ListResourcesResult(resources=resources).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    assert _floats(json.loads(json.dumps(wire))) == []
    for item in wire["resources"]:
        assert item["annotations"] == {"audience": ["assistant"]}
        assert isinstance(item["size"], int)
