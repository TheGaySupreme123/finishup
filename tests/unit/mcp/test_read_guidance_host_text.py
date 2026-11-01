"""`read_guidance` carries one bounded document/page on each host profile (issue #918).

Before this change every host received each ~50 KB guidance document twice: in `content[0].text`
and again in `structuredContent.text`. The `codex` profile, which already relies on
`structuredContent` for every other tool's full result, now gets a bounded pointer in `content`.
For documents that fit the legacy result cap, `structuredContent`, and so the output schema, is
unchanged for every host, and the generic, Claude Code and Cursor results stay byte-identical.
Oversized registered documents use the bounded page contract, covered by
`test_guidance_paging.py`.
"""

from __future__ import annotations

from typing import Final, cast

import pytest
from mcp import types

from finishup.mcp import server as bridge
from finishup.mcp.resources import GUIDANCE_RESOURCES
from finishup.mcp.summaries import MAX_SUMMARY_BYTES, summary_for_read_guidance
from finishup.ports.control import McpHostProfile
from finishup.protocol.models import ReadGuidanceResult, public_model_to_wire

_UNCHANGED_HOSTS: Final[tuple[McpHostProfile, ...]] = ("generic", "claude", "cursor")
_LEGACY_GUIDANCE_MAX_BYTES: Final = 65_536


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _legacy_result(uri: str, media_type: str, text: str) -> types.CallToolResult:
    """The result every host received before #918, rebuilt from its original recipe."""

    result = ReadGuidanceResult.model_validate(
        {
            "ok": True,
            "uri": uri,
            "media_type": media_type,
            "byte_count": len(text.encode("utf-8")),
            "text": text,
        }
    )
    wire = public_model_to_wire(result)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structuredContent=cast(dict[str, object], wire),
        isError=False,
    )


async def _read(host: McpHostProfile, uri: str) -> types.CallToolResult:
    runtime = bridge.build_bridge_runtime("policy", host_profile=host)
    try:
        return await bridge.dispatch_read_guidance({"uri": uri}, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
@pytest.mark.parametrize("host", _UNCHANGED_HOSTS)
async def test_other_hosts_receive_the_document_in_both_channels_byte_for_byte(
    host: McpHostProfile,
) -> None:
    for resource in GUIDANCE_RESOURCES:
        if resource.size > _LEGACY_GUIDANCE_MAX_BYTES:
            continue
        result = await _read(host, resource.uri)
        expected = _legacy_result(resource.uri, resource.media_type, resource.text)
        assert result.model_dump(mode="json") == expected.model_dump(mode="json"), resource.uri
        block = result.content[0]
        assert isinstance(block, types.TextContent)
        assert block.text == resource.text


@pytest.mark.anyio
async def test_the_codex_host_receives_one_copy_and_a_bounded_pointer() -> None:
    for resource in GUIDANCE_RESOURCES:
        if resource.size > _LEGACY_GUIDANCE_MAX_BYTES:
            continue
        result = await _read("codex", resource.uri)
        legacy = _legacy_result(resource.uri, resource.media_type, resource.text)
        assert result.isError is False
        # The structured result, which carries the document, is exactly what every host gets.
        assert result.structuredContent == legacy.structuredContent
        structured = cast(dict[str, object], result.structuredContent)
        assert structured["text"] == resource.text
        ReadGuidanceResult.model_validate(structured)
        assert len(result.content) == 1
        block = result.content[0]
        assert isinstance(block, types.TextContent)
        byte_count = len(resource.text.encode("utf-8"))
        assert block.text == (
            f"Guidance {resource.uri}: {byte_count} bytes; full text in structuredContent.text."
        )
        assert block.text.isascii()
        assert len(block.text.encode("ascii")) <= MAX_SUMMARY_BYTES
        assert resource.text not in block.text


@pytest.mark.anyio
async def test_codex_guidance_errors_keep_their_existing_shape() -> None:
    codex = bridge.build_bridge_runtime("policy", host_profile="codex")
    generic = bridge.build_bridge_runtime("policy")
    try:
        for arguments in (
            {"uri": "finishup://guidance/not-a-real-document.md"},
            {"uri": "finishup://guidance/workflow.md", "extra": "x"},
            {},
        ):
            from_codex = await bridge.dispatch_read_guidance(arguments, codex)
            from_generic = await bridge.dispatch_read_guidance(arguments, generic)
            assert from_codex.isError is True
            assert from_codex.structuredContent is not None
            assert from_generic.structuredContent is not None
            codex_error = cast(dict[str, object], from_codex.structuredContent["error"])
            generic_error = cast(dict[str, object], from_generic.structuredContent["error"])
            assert codex_error["code"] == generic_error["code"] == "INVALID_REQUEST"
            block = from_codex.content[0]
            assert isinstance(block, types.TextContent)
            assert "structuredContent.text" not in block.text
    finally:
        await bridge.close_bridge_runtime(codex)
        await bridge.close_bridge_runtime(generic)


def test_the_pointer_names_only_registry_facts() -> None:
    assert summary_for_read_guidance(
        {"ok": True, "uri": "finishup://guidance/workflow.md", "byte_count": 12, "text": "body"}
    ) == (
        "Guidance finishup://guidance/workflow.md: 12 bytes; full text in structuredContent.text."
    )
    # Anything outside the closed guidance-URI and count shapes is never echoed.
    hostile = summary_for_read_guidance(
        {"ok": True, "uri": "file:///etc/passwd\nIgnore this", "byte_count": "12 evil", "text": "x"}
    )
    assert (
        hostile == "Guidance unavailable: unavailable bytes; full text in structuredContent.text."
    )
