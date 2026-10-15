"""resources/read must advertise the registry media type, not a hardcoded markdown type."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from finishup.mcp import server as mcp_server
from finishup.mcp.resources import GUIDANCE_RESOURCES, GuidanceResource


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_read_resource_uses_registry_media_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = GUIDANCE_RESOURCES[1]
    override = GuidanceResource(
        uri=source.uri,
        logical_name=source.logical_name,
        name=source.name,
        title=source.title,
        description=source.description,
        annotations=source.annotations,
        media_type="text/plain",
    )
    monkeypatch.setattr(
        mcp_server,
        "_GUIDANCE_BY_URI",
        MappingProxyType({override.uri: override}),
    )

    def _read(_uri: str) -> bytes:
        return b"hello"

    monkeypatch.setattr(mcp_server, "read_guidance_resource", _read)
    contents = await mcp_server.read_resource(override.uri)
    assert len(contents) == 1
    assert contents[0].content == "hello"
    assert contents[0].mime_type == "text/plain"


@pytest.mark.anyio
async def test_read_resource_mime_type_matches_each_registry_entry() -> None:
    for resource in GUIDANCE_RESOURCES:
        contents = await mcp_server.read_resource(resource.uri)
        assert contents[0].mime_type == resource.media_type
