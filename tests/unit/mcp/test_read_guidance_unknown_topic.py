"""Unknown guidance topic anchors fail with the registered alternatives (benchmark full3)."""

from __future__ import annotations

from typing import cast

import pytest

from yoetz.mcp import server as bridge
from yoetz.mcp.summaries import summary_for_read_guidance
from yoetz.protocol.guidance_uris import GUIDANCE_DOCUMENT_URIS, GUIDANCE_TOPIC_URIS

_TEMPLATES = "yoetz://guidance/request-templates.md"


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    return cast(dict[str, object], structured["error"])


@pytest.mark.anyio
@pytest.mark.parametrize(
    "anchor",
    (
        # Shapes observed in real agent requests: guessed from tool names, with underscores, and
        # derived from event-family names. None is in the closed catalog.
        "publish-work",
        "publish_work-plan-revision",
        "plan-revised",
    ),
)
async def test_unknown_anchor_lists_the_documents_registered_anchors(anchor: str) -> None:
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")
    try:
        result = await bridge.dispatch_read_guidance({"uri": f"{_TEMPLATES}#{anchor}"}, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert result.isError is True
    error = _error(result)
    assert error["code"] == "INVALID_REQUEST"
    assert error["safe_details"] == {"field": "/uri"}
    message = cast(str, error["message"])
    expected = [uri.partition("#")[2] for uri in GUIDANCE_TOPIC_URIS if uri.startswith(_TEMPLATES)]
    assert expected
    for registered in expected:
        assert registered in message
    assert f"Retry with uri {_TEMPLATES} " in message
    # The caller's anchor is never echoed; only catalog constants are.
    if anchor not in expected and all(anchor not in registered for registered in expected):
        assert anchor not in message
    assert len(message.encode("utf-8")) <= 4096


@pytest.mark.anyio
async def test_every_document_anchor_list_fits_the_public_message_bound() -> None:
    runtime = bridge.build_bridge_runtime("policy")
    try:
        for document in GUIDANCE_DOCUMENT_URIS:
            result = await bridge.dispatch_read_guidance({"uri": f"{document}#zz-unknown"}, runtime)
            message = cast(str, _error(result)["message"])
            assert document in message
            assert "zz-unknown" not in message
    finally:
        await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_unknown_document_lists_registered_documents_without_echo() -> None:
    runtime = bridge.build_bridge_runtime("policy")
    try:
        result = await bridge.dispatch_read_guidance(
            {"uri": "yoetz://guidance/not-a-real-document.md"}, runtime
        )
    finally:
        await bridge.close_bridge_runtime(runtime)
    message = cast(str, _error(result)["message"])
    assert "not-a-real-document" not in message
    for document in GUIDANCE_DOCUMENT_URIS:
        assert document in message


@pytest.mark.anyio
async def test_registered_topic_still_reads() -> None:
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")
    try:
        result = await bridge.dispatch_read_guidance(
            {"uri": "yoetz://guidance/workflow.md#start-and-resume"}, runtime
        )
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert result.isError is False


def test_successful_topic_read_is_not_labelled_unavailable() -> None:
    text = summary_for_read_guidance(
        {"ok": True, "uri": "yoetz://guidance/workflow.md#start-and-resume", "byte_count": 7}
    )
    assert text == (
        "Guidance yoetz://guidance/workflow.md#start-and-resume: 7 bytes; "
        "full text in structuredContent.text."
    )
    # An unregistered anchor is still withheld rather than echoed.
    assert "unavailable" in summary_for_read_guidance(
        {"ok": True, "uri": "yoetz://guidance/workflow.md#made-up", "byte_count": 7}
    )


@pytest.mark.anyio
@pytest.mark.parametrize("profile", ("codex", "claude", "generic"))
async def test_unknown_anchor_text_content_names_valid_anchors_without_echo(profile: str) -> None:
    runtime = bridge.build_bridge_runtime(
        "policy", host_profile=cast(bridge.McpHostProfile, profile)
    )
    try:
        result = await bridge.dispatch_read_guidance(
            {"uri": f"{_TEMPLATES}#zz-guessed-anchor"}, runtime
        )
    finally:
        await bridge.close_bridge_runtime(runtime)
    text = "".join(getattr(part, "text", "") for part in result.content)
    assert "publication-templates" in text
    assert f"Retry with uri {_TEMPLATES} " in text
    assert "zz-guessed-anchor" not in text
