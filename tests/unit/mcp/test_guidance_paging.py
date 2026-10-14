"""Bounded guidance delivery and host-side reconstruction checks."""

from __future__ import annotations

import hashlib
from typing import Any, cast

import pytest
from mcp import types

from yoetz.mcp import resources as resource_module
from yoetz.mcp import server as bridge
from yoetz.mcp.resources import (
    GuidanceAssemblyError,
    GuidancePageAssembler,
    GuidanceResourceError,
    GuidanceResourcePage,
    _page_boundaries,  # pyright: ignore[reportPrivateUsage]
    read_resource_page,
)
from yoetz.ports.control import McpHostProfile
from yoetz.protocol.models import ReadGuidanceRequestModel

_URI = "yoetz://guidance/agent-instructions.md"
_OVERSIZED_URI = "yoetz://guidance/workflow.md"


def _wire(page: GuidanceResourcePage) -> dict[str, object]:
    result: dict[str, object] = {
        "ok": True,
        "uri": page.resource.uri,
        "media_type": page.resource.media_type,
        "byte_count": page.byte_count,
        "text": page.text,
        "document_id": page.resource.uri,
        "revision": page.revision,
        "digest": page.digest,
        "total_byte_count": page.total_byte_count,
        "page": str(page.page),
        "page_size": str(page.page_size),
        "page_offset": page.offset,
        "page_byte_count": page.byte_count,
        "page_count": str(page.page_count),
        "complete": page.complete,
    }
    if page.continuation is not None:
        result["continuation"] = page.continuation
    return result


def _host_text(page: GuidanceResourcePage) -> str:
    next_page = "none" if page.next_page is None else str(page.next_page)
    complete = "yes" if page.complete else "no"
    return (
        f"YOETZ_GUIDANCE_PAGE_BEGIN document={page.resource.uri} page={page.page} "
        f"page_count={page.page_count} offset={page.offset} bytes={page.byte_count} "
        f"total_bytes={page.total_byte_count} revision={page.revision} digest={page.digest}\n"
        f"{page.text}\n"
        f"YOETZ_GUIDANCE_PAGE_END complete={complete} next_page={next_page} "
        f"revision={page.revision} digest={page.digest}"
    )


def test_utf8_page_boundaries_never_split_a_scalar() -> None:
    payload = "a🙂b".encode()
    boundaries = _page_boundaries(payload, 4)
    assert boundaries == (0, 1, 5, 6)
    assert [
        payload[start:end].decode("utf-8") for start, end in zip(boundaries, boundaries[1:])
    ] == [
        "a",
        "🙂",
        "b",
    ]


def test_empty_guidance_document_is_one_complete_page(monkeypatch: pytest.MonkeyPatch) -> None:
    def empty_resource(_name: str) -> bytes:
        return b""

    monkeypatch.setattr(resource_module, "read_verified_resource", empty_resource)
    page = read_resource_page(_URI, page_size=4)
    assert page.page_count == 1
    assert page.complete is True
    assert page.text == ""
    assembler = GuidancePageAssembler()
    assembler.add(_wire(page), host_text=_host_text(page))
    assert assembler.assemble() == ""


def test_host_assembler_reconstructs_small_pages_and_checks_digest() -> None:
    assembler = GuidancePageAssembler()
    pages: list[GuidanceResourcePage] = []
    page_number = 0
    while True:
        page = read_resource_page(_URI, page=page_number, page_size=257)
        pages.append(page)
        assembler.add(_wire(page), host_text=_host_text(page))
        if page.complete:
            break
        page_number += 1

    assert assembler.received_pages == tuple(range(len(pages)))
    assert assembler.assemble() == read_resource_page(_URI, page_size=16_384).resource.text


def test_host_assembler_reconstructs_the_oversized_real_document() -> None:
    assembler = GuidancePageAssembler()
    page_number = 0
    while True:
        page = read_resource_page(_OVERSIZED_URI, page=page_number)
        assembler.add(_wire(page), host_text=_host_text(page))
        if page.complete:
            break
        page_number += 1

    assert page.total_byte_count > 65_536
    assert assembler.assemble() == page.resource.text


def test_page_count_must_cover_document_at_requested_page_size() -> None:
    page = read_resource_page(_URI, page_size=64)
    wire = _wire(page)
    wire["page_count"] = "1"
    wire["complete"] = True
    wire.pop("continuation")
    with pytest.raises(GuidanceAssemblyError, match="guidance_page_count_invalid"):
        GuidancePageAssembler().add(wire)


def test_too_small_page_size_rejects_an_oversized_document_page_count() -> None:
    with pytest.raises(GuidanceResourceError, match="guidance_page_count_invalid"):
        read_resource_page(_OVERSIZED_URI, page_size=4)


def test_host_assembler_rejects_missing_or_clipped_model_output() -> None:
    page = read_resource_page(_URI, page_size=64)
    with pytest.raises(GuidanceAssemblyError, match="guidance_host_delivery_missing"):
        GuidancePageAssembler().add(_wire(page))
    with pytest.raises(GuidanceAssemblyError, match="guidance_host_delivery_incomplete"):
        GuidancePageAssembler().add(_wire(page), host_text=_host_text(page)[:-1])

    final = read_resource_page(
        _URI, page=read_resource_page(_URI, page_size=64).page_count - 1, page_size=64
    )
    assert final.complete is True
    final_only = GuidancePageAssembler(host_proof_required=False)
    final_only.add(_wire(final))
    with pytest.raises(GuidanceAssemblyError, match="guidance_pages_missing"):
        final_only.assemble()


def test_empty_host_result_is_incomplete_even_when_the_page_is_nonempty() -> None:
    page = read_resource_page(_URI, page_size=64)
    with pytest.raises(GuidanceAssemblyError, match="guidance_host_delivery_incomplete"):
        GuidancePageAssembler().add(_wire(page), host_text="")


def test_host_assembler_rejects_missing_pages_duplicate_pages_and_offset_gaps() -> None:
    first = read_resource_page(_URI, page=0, page_size=64)

    assembler = GuidancePageAssembler()
    assembler.add(_wire(first), host_text=_host_text(first))
    with pytest.raises(GuidanceAssemblyError, match="guidance_page_duplicate"):
        assembler.add(_wire(first), host_text=_host_text(first))
    with pytest.raises(GuidanceAssemblyError, match="guidance_pages_missing"):
        assembler.assemble()

    digest = "sha256:" + hashlib.sha256(b"abcdefg").hexdigest()
    gap_first = {
        "ok": True,
        "uri": _URI,
        "document_id": _URI,
        "revision": digest,
        "digest": digest,
        "total_byte_count": 8,
        "page": "0",
        "page_size": "4",
        "page_offset": 0,
        "page_byte_count": 3,
        "page_count": "2",
        "complete": False,
        "text": "abc",
        "continuation": {
            "uri": _URI,
            "page": "1",
            "page_size": "4",
            "revision": digest,
            "digest": digest,
        },
    }
    gap_second = dict(gap_first)
    gap_second.update(
        page="1",
        page_offset=4,
        complete=True,
        page_byte_count=4,
        text="defg",
    )
    gap_second.pop("continuation")
    gap_assembler = GuidancePageAssembler(host_proof_required=False)
    gap_assembler.add(gap_first)
    gap_assembler.add(gap_second)
    with pytest.raises(GuidanceAssemblyError, match="guidance_page_offset_gap"):
        gap_assembler.assemble()


def test_dispatch_paged_result_has_bounded_markers_and_stale_recovery() -> None:
    async def _run() -> None:
        runtime = bridge.build_bridge_runtime("policy", host_profile="generic")
        try:
            result = await bridge.dispatch_read_guidance(
                {"uri": _URI, "page": "0", "page_size": "64"}, runtime
            )
            assert result.isError is False
            wire = cast(dict[str, object], result.structuredContent)
            assert wire["page"] == "0"
            assert wire["page_size"] == "64"
            block = result.content[0]
            assert isinstance(block, types.TextContent)
            assert block.text.startswith("YOETZ_GUIDANCE_PAGE_BEGIN ")
            assert block.text.endswith(f"digest={wire['digest']}")
            assert isinstance(wire["text"], str)
            assert wire["text"] in block.text

            stale = await bridge.dispatch_read_guidance(
                {
                    "uri": _URI,
                    "page": "0",
                    "page_size": "64",
                    "digest": "sha256:" + "0" * 64,
                },
                runtime,
            )
            assert stale.isError is True
            error = cast(dict[str, Any], cast(dict[str, object], stale.structuredContent)["error"])
            assert error["code"] == "INVALID_REQUEST"
            assert "sha256:" + "0" * 64 not in repr(stale.structuredContent)
        finally:
            await bridge.close_bridge_runtime(runtime)

    import anyio

    anyio.run(_run)


def test_legacy_oversized_dispatch_returns_bounded_first_page_with_continuation() -> None:
    """A URI-only read of a real oversized resource enters the page contract automatically."""

    async def _run() -> None:
        runtime = bridge.build_bridge_runtime("policy", host_profile="generic")
        try:
            result = await bridge.dispatch_read_guidance({"uri": _OVERSIZED_URI}, runtime)
            assert result.isError is False
            wire = cast(dict[str, object], result.structuredContent)
            assert wire["uri"] == _OVERSIZED_URI
            assert wire["document_id"] == _OVERSIZED_URI
            assert wire["page"] == "0"
            assert wire["page_size"] == str(resource_module.DEFAULT_GUIDANCE_PAGE_SIZE)
            assert wire["page_offset"] == 0
            assert wire["complete"] is False
            assert int(cast(int, wire["total_byte_count"])) > 65_536
            assert int(cast(str, wire["page_count"])) > 1
            continuation = cast(dict[str, object], wire["continuation"])
            assert continuation["uri"] == _OVERSIZED_URI
            assert continuation["page"] == "1"
            assert continuation["page_size"] == wire["page_size"]
            page_text = wire["text"]
            page_size = wire["page_size"]
            assert isinstance(page_text, str)
            assert isinstance(page_size, str)
            assert len(page_text.encode("utf-8")) <= int(page_size)
            block = result.content[0]
            assert isinstance(block, types.TextContent)
            assert len(block.text.encode("utf-8")) < 1_100_000
        finally:
            await bridge.close_bridge_runtime(runtime)

    import anyio

    anyio.run(_run)


def test_hostile_page_sizes_fail_closed() -> None:
    with pytest.raises(GuidanceResourceError, match="guidance_page_size_invalid"):
        read_resource_page(_URI, page_size=3)


@pytest.mark.parametrize("page_size", ("4", "16384"))
def test_request_accepts_the_inclusive_guidance_page_size_bounds(page_size: str) -> None:
    request = ReadGuidanceRequestModel.model_validate(
        {"uri": _URI, "page": "0", "page_size": page_size}
    )
    assert request.page_size == page_size


@pytest.mark.parametrize("page_size", ("3", "16385", "016384"))
def test_request_rejects_noncanonical_or_out_of_range_guidance_page_sizes(
    page_size: str,
) -> None:
    with pytest.raises(ValueError, match="guidance_page_size_invalid|canonical"):
        ReadGuidanceRequestModel.model_validate({"uri": _URI, "page": "0", "page_size": page_size})


def test_dispatch_rejects_oversized_page_size_with_a_field_local_retry() -> None:
    async def _run() -> None:
        runtime = bridge.build_bridge_runtime("policy", host_profile="generic")
        try:
            result = await bridge.dispatch_read_guidance(
                {"uri": _URI, "page": "0", "page_size": "16385"}, runtime
            )
            assert result.isError is True
            error = cast(dict[str, Any], cast(dict[str, object], result.structuredContent)["error"])
            assert error["code"] == "INVALID_REQUEST"
            assert "page_size" in error["message"]
            assert "16384" in error["message"]
            assert "4096" in error["message"]
            details = cast(dict[str, object], error["safe_details"])
            assert "/page_size" in cast(list[object], details["fields"])
            assert "guidance_page_size_invalid" in cast(list[object], details["reasons"])
        finally:
            await bridge.close_bridge_runtime(runtime)

    import anyio

    anyio.run(_run)


@pytest.mark.parametrize("host", ("codex", "generic", "claude", "cursor"))
def test_paged_route_accepts_supported_host_profiles(host: McpHostProfile) -> None:
    async def _run() -> None:
        runtime = bridge.build_bridge_runtime("policy", host_profile=host)
        try:
            result = await bridge.dispatch_read_guidance(
                {"uri": _URI, "page": "0", "page_size": "64"}, runtime
            )
            assert result.isError is False
            assert result.structuredContent is not None
        finally:
            await bridge.close_bridge_runtime(runtime)

    import anyio

    anyio.run(_run)


@pytest.mark.parametrize("host", ("codex", "claude", "cursor"))
def test_paged_route_reconstructs_every_document_on_each_host_projection(
    host: McpHostProfile,
) -> None:
    async def _run() -> None:
        runtime = bridge.build_bridge_runtime("policy", host_profile=host)
        try:
            for resource in resource_module.GUIDANCE_RESOURCES:
                assembler = GuidancePageAssembler(host_proof_required=host != "codex")
                arguments: dict[str, object] = {
                    "uri": resource.uri,
                    "page": "0",
                    "page_size": "4096",
                }
                while True:
                    result = await bridge.dispatch_read_guidance(arguments, runtime)
                    assert result.isError is False
                    assert result.structuredContent is not None
                    wire = cast(dict[str, object], result.structuredContent)
                    block = result.content[0]
                    assert isinstance(block, types.TextContent)
                    assembler.add(
                        wire,
                        host_text=None if host == "codex" else block.text,
                    )
                    if wire["complete"] is True:
                        break
                    continuation = wire.get("continuation")
                    assert isinstance(continuation, dict)
                    arguments = dict(cast(dict[str, object], continuation))
                assert assembler.assemble() == resource.text
        finally:
            await bridge.close_bridge_runtime(runtime)

    import anyio

    anyio.run(_run)
