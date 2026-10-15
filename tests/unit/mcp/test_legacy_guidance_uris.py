"""Pre-rename ``yoetz://guidance/`` URIs still read the packaged guidance (ADR-048).

Installed 0.1-0.3 guidance, skills and host artifacts, and the released read-guidance 1.0.0
contract, name ``yoetz://``. A legacy URI is admitted only as the exact legacy spelling of a
catalogued entry, reads the same bytes, and is answered in the scheme the caller used. The
resource listing advertises the current ``finishup://`` spelling only.
"""

from __future__ import annotations

from typing import cast

import pytest
from mcp import types
from pydantic import ValidationError

from finishup.mcp import server as bridge
from finishup.mcp.resources import (
    list_resources,
    read_resource,
    read_resource_page,
    resolve_guidance_topic_uri,
    resource_for_uri,
)
from finishup.mcp.summaries import summary_for_read_guidance
from finishup.protocol.guidance_uris import (
    ALL_GUIDANCE_URIS,
    LEGACY_ALL_GUIDANCE_URIS,
    LEGACY_GUIDANCE_ANCHORS,
    canonical_guidance_uri,
    guidance_uri_in_scheme_of,
    is_legacy_guidance_uri,
    legacy_guidance_uri,
)
from finishup.protocol.models import ReadGuidanceRequestModel
from finishup.protocol.schemas import validate_schema_instance

_LEGACY_WORKFLOW = "yoetz://guidance/workflow.md"
_CURRENT_WORKFLOW = "finishup://guidance/workflow.md"


def _structured(result: types.CallToolResult) -> dict[str, object]:
    return cast(dict[str, object], result.structuredContent)


def test_the_legacy_catalog_is_the_exact_spelling_of_every_current_entry() -> None:
    assert len(LEGACY_ALL_GUIDANCE_URIS) == len(ALL_GUIDANCE_URIS)
    assert all(uri.startswith("yoetz://guidance/") for uri in LEGACY_ALL_GUIDANCE_URIS)
    for legacy, current in zip(LEGACY_ALL_GUIDANCE_URIS, ALL_GUIDANCE_URIS, strict=True):
        assert canonical_guidance_uri(legacy) == current
        assert canonical_guidance_uri(current) == current
        assert legacy_guidance_uri(current) == legacy
        assert is_legacy_guidance_uri(legacy)
        assert not is_legacy_guidance_uri(current)
    # The four title anchors that carried the old product name keep their old spelling.
    for legacy_anchor, current_anchor in LEGACY_GUIDANCE_ANCHORS.items():
        assert f"yoetz://guidance/{legacy_anchor}" in LEGACY_ALL_GUIDANCE_URIS
        assert f"finishup://guidance/{current_anchor}" in ALL_GUIDANCE_URIS
    assert (
        canonical_guidance_uri("yoetz://guidance/workflow.md#finishup-cooperative-workflow") is None
    )
    assert canonical_guidance_uri("yoetz://guidance/unknown.md") is None
    assert canonical_guidance_uri(None) is None


def test_resources_list_advertises_the_current_scheme_only() -> None:
    uris = [resource.uri for resource in list_resources()]
    assert uris
    assert all(uri.startswith("finishup://guidance/") for uri in uris)


@pytest.mark.parametrize(
    "uri",
    (
        _LEGACY_WORKFLOW,
        "yoetz://guidance/startup.md",
        "yoetz://guidance/workflow.md#start-and-resume",
        "yoetz://guidance/workflow.md#yoetz-cooperative-workflow",
        "yoetz://guidance/agent-instructions.md#when-to-use-yoetz",
    ),
)
def test_resources_read_accepts_the_legacy_spelling_and_keeps_it(uri: str) -> None:
    current = canonical_guidance_uri(uri)
    assert current is not None
    assert read_resource(uri) == read_resource(current)
    resource = resource_for_uri(uri)
    assert resource.uri == uri
    assert resource.bytes == resource_for_uri(current).bytes


def test_a_legacy_page_continuation_stays_in_the_legacy_scheme() -> None:
    page = read_resource_page(_LEGACY_WORKFLOW, page=0, page_size=1024)
    assert not page.complete
    continuation = page.continuation
    assert continuation is not None
    assert continuation["uri"] == _LEGACY_WORKFLOW
    assert page.text == read_resource_page(_CURRENT_WORKFLOW, page=0, page_size=1024).text


@pytest.mark.parametrize(
    ("guess", "expected"),
    (
        (
            "yoetz://guidance/request-templates.md#decision",
            "yoetz://guidance/request-templates.md#publish-work-decision",
        ),
        (
            "yoetz://guidance/workflow.md#finishup-cooperative-workflow",
            "yoetz://guidance/workflow.md#yoetz-cooperative-workflow",
        ),
        (
            "finishup://guidance/workflow.md#yoetz-cooperative-workflow",
            "finishup://guidance/workflow.md#finishup-cooperative-workflow",
        ),
        (
            "finishup://guidance/request-templates.md#decision",
            "finishup://guidance/request-templates.md#publish-work-decision",
        ),
    ),
)
def test_a_guessed_anchor_resolves_in_the_callers_scheme(guess: str, expected: str) -> None:
    assert resolve_guidance_topic_uri(guess) == expected


def test_scheme_rendering_follows_the_caller() -> None:
    current = "finishup://guidance/workflow.md#finishup-cooperative-workflow"
    assert guidance_uri_in_scheme_of(current, current) == current
    assert (
        guidance_uri_in_scheme_of(current, "yoetz://guidance/workflow.md#anything")
        == "yoetz://guidance/workflow.md#yoetz-cooperative-workflow"
    )


def test_the_request_model_admits_both_spellings_and_nothing_else() -> None:
    for uri in (_LEGACY_WORKFLOW, _CURRENT_WORKFLOW):
        assert ReadGuidanceRequestModel.model_validate({"uri": uri}).uri == uri
    for uri in ("yoetz://guidance/unknown.md", "yoetz://guidance/workflow.md#not-a-topic"):
        with pytest.raises(ValidationError):
            ReadGuidanceRequestModel.model_validate({"uri": uri})


def test_the_released_contract_admits_a_legacy_read() -> None:
    # The released 1.0.0 request enumerates the pre-rename documents; the current version admits
    # either scheme by pattern while the runtime catalog stays the admission rule.
    validate_schema_instance("read-guidance-request", "1.0.0", {"uri": _LEGACY_WORKFLOW})
    for uri in (_LEGACY_WORKFLOW, _CURRENT_WORKFLOW):
        validate_schema_instance("read-guidance-request", "1.1.0", {"uri": uri})


@pytest.mark.anyio
@pytest.mark.parametrize(
    "uri",
    (
        _LEGACY_WORKFLOW,
        "yoetz://guidance/consent.md",
        "yoetz://guidance/workflow.md#yoetz-cooperative-workflow",
        "yoetz://guidance/request-templates.md#yoetz-request-templates-and-exceptional-operations",
    ),
)
async def test_read_guidance_answers_a_legacy_read_in_the_legacy_scheme(uri: str) -> None:
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")
    try:
        legacy = await bridge.dispatch_read_guidance({"uri": uri}, runtime)
        current_uri = canonical_guidance_uri(uri)
        assert current_uri is not None
        current = await bridge.dispatch_read_guidance({"uri": current_uri}, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert legacy.isError is False
    legacy_body = _structured(legacy)
    current_body = _structured(current)
    assert legacy_body["uri"] == uri
    assert current_body["uri"] == current_uri
    assert legacy_body["text"] == current_body["text"]
    continuation = legacy_body.get("continuation")
    if continuation is not None:
        assert cast(dict[str, object], continuation)["uri"] == uri
        assert legacy_body["document_id"] == uri
    assert uri in summary_for_read_guidance(legacy_body)


@pytest.mark.anyio
async def test_read_guidance_still_refuses_an_unregistered_legacy_uri() -> None:
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")
    try:
        result = await bridge.dispatch_read_guidance(
            {"uri": "yoetz://guidance/unknown.md"}, runtime
        )
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert result.isError is True
    error = cast(dict[str, object], _structured(result)["error"])
    assert error["code"] == "INVALID_REQUEST"
    assert "unknown.md" not in cast(str, error["message"])


@pytest.mark.anyio
async def test_an_unknown_anchor_in_a_legacy_document_lists_that_documents_anchors() -> None:
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")
    try:
        legacy = await bridge.dispatch_read_guidance(
            {"uri": "yoetz://guidance/workflow.md#zzqx-no-such-topic"}, runtime
        )
        current = await bridge.dispatch_read_guidance(
            {"uri": "finishup://guidance/workflow.md#zzqx-no-such-topic"}, runtime
        )
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert legacy.isError is True
    legacy_message = cast(str, cast(dict[str, object], _structured(legacy)["error"])["message"])
    current_message = cast(str, cast(dict[str, object], _structured(current)["error"])["message"])
    # The same per-document catalog, listed in the current spelling; the guess is never echoed.
    assert legacy_message == current_message
    assert "has no topic with that anchor in finishup://guidance/workflow.md" in legacy_message
    assert "zzqx" not in legacy_message


def test_new_descriptor_and_initialize_text_names_only_the_current_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Readers accept ``yoetz://``; text FinishUP advertises must not reintroduce it (ADR-048)."""

    from finishup.mcp import descriptors

    budget = dict(descriptors.COMPACT_INSTRUCTIONS_BUDGET)
    current = descriptors.COMPACT_INITIALIZE_INSTRUCTIONS
    assert "yoetz://" not in current
    monkeypatch.setattr(
        descriptors,
        "COMPACT_INITIALIZE_INSTRUCTIONS",
        current + " finishup://guidance/workflow.md",
    )
    monkeypatch.setattr(
        descriptors,
        "COMPACT_INSTRUCTIONS_BUDGET",
        {**budget, "packaged_max_encoded_bytes": 1 << 20, "max_encoded_bytes": 1 << 21},
    )
    descriptors._lint_compact_initialize_instructions()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(
        descriptors,
        "COMPACT_INITIALIZE_INSTRUCTIONS",
        current + " yoetz://guidance/workflow.md",
    )
    with pytest.raises(RuntimeError, match="descriptor_boundary_lint_failed"):
        descriptors._lint_compact_initialize_instructions()  # pyright: ignore[reportPrivateUsage]
