"""Page zero of a paged guidance read names the resource's sections (tb4n5).

tb4n5 agents read the 80 KB request-templates page whole 34 times in 15 of 18 attempts: the
URI-only read returned page 0, which held no request body, and they paged, ran ``sed`` ranges or
guessed anchors. Page zero now carries the catalogued sections inside the resource, generated from
the same closed catalog ``read_guidance`` admits anchors from, so the list cannot drift. These tests
lock the structured field, each host's text rendering, the assembler's tolerance of the advisory
list, and that the remaining hand-written routing rows name catalogued anchors.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final, cast

import anyio
import pytest
from mcp import types

from yoetz.mcp import server as bridge
from yoetz.mcp.resources import (
    GUIDANCE_SECTIONS_MARKER,
    MAX_GUIDANCE_SECTIONS,
    GuidanceAssemblyError,
    GuidancePageAssembler,
    guidance_sections,
    resource_for_uri,
)
from yoetz.ports.control import McpHostProfile
from yoetz.protocol.guidance_uris import (
    FOCUSED_GUIDANCE_URIS,
    GUIDANCE_DOCUMENT_URIS,
    GUIDANCE_TOPIC_URIS,
)
from yoetz.protocol.models import ReadGuidanceResult

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_TEMPLATES: Final = "yoetz://guidance/request-templates.md"


async def _read(arguments: dict[str, object], host: McpHostProfile) -> types.CallToolResult:
    runtime = bridge.build_bridge_runtime("policy", host_profile=host)
    try:
        return await bridge.dispatch_read_guidance(arguments, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)


def _call(arguments: dict[str, object], host: McpHostProfile = "generic") -> types.CallToolResult:
    async def _run() -> types.CallToolResult:
        return await _read(arguments, host)

    return anyio.run(_run)


@pytest.mark.parametrize("document", GUIDANCE_DOCUMENT_URIS)
def test_a_document_lists_every_catalogued_topic_in_document_order(document: str) -> None:
    sections = guidance_sections(document)
    catalogued = {uri for uri in GUIDANCE_TOPIC_URIS if uri.startswith(document + "#")}
    assert {section.uri for section in sections} == catalogued
    assert 0 < len(sections) <= MAX_GUIDANCE_SECTIONS
    starts = [resource_for_uri(section.uri).section_start for section in sections]
    assert starts == sorted(cast(list[int], starts))
    for section in sections:
        assert section.byte_count == resource_for_uri(section.uri).size


def test_a_heading_topic_lists_only_the_topics_inside_it_and_a_focused_topic_none() -> None:
    topic = "yoetz://guidance/workflow.md#delegation-and-project-coordination"
    resource = resource_for_uri(topic)
    inside = guidance_sections(topic)
    assert inside
    for section in inside:
        start = cast(int, resource_for_uri(section.uri).section_start)
        assert cast(int, resource.section_start) <= start < cast(int, resource.section_end)
        assert section.uri != topic
    for focused in FOCUSED_GUIDANCE_URIS:
        assert guidance_sections(focused) == ()


def test_page_zero_of_an_oversized_uri_only_read_carries_the_sections() -> None:
    result = _call({"uri": _TEMPLATES})
    assert result.isError is False
    wire = cast(dict[str, object], result.structuredContent)
    assert wire["page"] == "0"
    listed = cast(list[dict[str, object]], wire["sections"])
    assert [entry["uri"] for entry in listed] == [s.uri for s in guidance_sections(_TEMPLATES)]
    assert f"{_TEMPLATES}#publish-work-action" in {entry["uri"] for entry in listed}
    # Every listed section is itself a readable, unpaged read.
    for entry in listed:
        section = _call({"uri": cast(str, entry["uri"])})
        assert section.isError is False
        assert (
            cast(dict[str, object], section.structuredContent)["byte_count"] == entry["byte_count"]
        )


def test_later_pages_and_unpaged_reads_carry_no_sections() -> None:
    first = cast(dict[str, object], _call({"uri": _TEMPLATES}).structuredContent)
    continuation = cast(dict[str, object], first["continuation"])
    second = cast(dict[str, object], _call(dict(continuation)).structuredContent)
    assert second["page"] == "1"
    assert "sections" not in second
    # A document small enough for one response is returned whole, with no page metadata.
    whole = cast(
        dict[str, object],
        _call({"uri": "yoetz://guidance/agent-instructions.md"}).structuredContent,
    )
    assert "page" not in whole
    assert "sections" not in whole
    # A focused topic has no catalogued sections even when paged.
    focused = cast(
        dict[str, object],
        _call(
            {"uri": "yoetz://guidance/startup.md", "page": "0", "page_size": "1024"}
        ).structuredContent,
    )
    assert focused["page"] == "0"
    assert "sections" not in focused


@pytest.mark.parametrize("host", ("generic", "claude", "cursor"))
def test_text_hosts_append_the_list_after_the_end_marker_and_still_assemble(
    host: McpHostProfile,
) -> None:
    result = _call({"uri": _TEMPLATES}, host)
    wire = cast(dict[str, object], result.structuredContent)
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    assert len(result.content) == 1
    end = f"YOETZ_GUIDANCE_PAGE_END complete=no next_page=1 revision={wire['revision']}"
    head, marker, trailer = block.text.partition(f"\n{GUIDANCE_SECTIONS_MARKER} ")
    assert marker
    assert end in head.rsplit("\n", 1)[-1]
    assert trailer.startswith(f"document={_TEMPLATES} count={len(guidance_sections(_TEMPLATES))}\n")
    assert f"read_guidance with uri {_TEMPLATES}#<anchor>" in trailer
    assert "\n#publish-work-action " in trailer
    # The list is outside the page bytes: the assembler checks exactly the text between markers.
    assembler = GuidancePageAssembler()
    assembler.add(wire, host_text=block.text)
    assert assembler.received_pages == (0,)


def test_codex_names_the_sections_beside_the_structured_page_pointer() -> None:
    result = _call({"uri": _TEMPLATES}, "codex")
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    assert "full page in structuredContent.text." in block.text
    assert "sections in structuredContent.sections; read only the one you need" in block.text
    assert "#publish-work-action" in block.text
    assert GUIDANCE_SECTIONS_MARKER not in block.text


def test_the_assembler_accepts_the_list_only_after_page_zeros_end_marker() -> None:
    first = _call({"uri": _TEMPLATES})
    wire = cast(dict[str, object], first.structuredContent)
    text = cast(types.TextContent, first.content[0]).text
    page_text, _marker, _trailer = text.partition(f"\n{GUIDANCE_SECTIONS_MARKER} ")
    # A clipped page with an intact list is still a clipped page.
    clipped = page_text[: len(page_text) // 2] + text[len(page_text) :]
    with pytest.raises(GuidanceAssemblyError, match="guidance_host_delivery_incomplete"):
        GuidancePageAssembler().add(wire, host_text=clipped)
    # Any other text after the end marker is still rejected.
    with pytest.raises(GuidanceAssemblyError, match="guidance_host_delivery_incomplete"):
        GuidancePageAssembler().add(wire, host_text=page_text + "\nextra")
    second = _call(dict(cast(dict[str, object], wire["continuation"])))
    second_wire = cast(dict[str, object], second.structuredContent)
    second_text = cast(types.TextContent, second.content[0]).text
    assert GUIDANCE_SECTIONS_MARKER not in second_text
    assembler = GuidancePageAssembler()
    assembler.add(wire, host_text=text)
    with pytest.raises(GuidanceAssemblyError, match="guidance_host_delivery_incomplete"):
        assembler.add(
            second_wire, host_text=f"{second_text}\n{GUIDANCE_SECTIONS_MARKER} document=x count=1"
        )


def test_the_result_model_admits_sections_only_on_page_zero_of_the_same_document() -> None:
    wire = dict(cast(dict[str, object], _call({"uri": _TEMPLATES}).structuredContent))
    ReadGuidanceResult.model_validate(wire)
    with pytest.raises(ValueError, match="guidance_sections_page_invalid"):
        ReadGuidanceResult.model_validate(
            {
                **wire,
                "page": "1",
                "page_offset": 4096,
                "continuation": {**cast(dict[str, object], wire["continuation"]), "page": "2"},
            }
        )
    foreign = [{"uri": "yoetz://guidance/workflow.md#cadence", "byte_count": 1}]
    with pytest.raises(ValueError, match="guidance_sections_document_mismatch"):
        ReadGuidanceResult.model_validate({**wire, "sections": foreign})
    unpaged = {
        key: wire[key] for key in ("ok", "uri", "media_type", "byte_count", "text", "sections")
    }
    with pytest.raises(ValueError, match="guidance_page_metadata_incomplete"):
        ReadGuidanceResult.model_validate(unpaged)


@pytest.mark.parametrize(
    "relative",
    (
        "guidance/request-templates.md",
        "guidance/workflow.md",
        "guidance/coverage-and-receipts.md",
        "guidance/publication-policy.md",
    ),
)
def test_the_remaining_hand_written_routes_name_catalogued_anchors(relative: str) -> None:
    """The generated list replaced the obvious rows; the rows left must not drift either."""

    text = (_REPO_ROOT / relative).read_text(encoding="utf-8")
    document = f"yoetz://guidance/{Path(relative).name}"
    opening = text.split("\n## ", 1)[0]
    anchors = re.findall(r"`#([a-z0-9-]+)`", opening)
    assert anchors, relative
    for anchor in anchors:
        assert f"{document}#{anchor}" in GUIDANCE_TOPIC_URIS, anchor
